/**
 * OpenParliament.ca REST Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: OpenParliament.ca — civic-tech mirror of the Parliament of Canada
 * Base URL: https://api.openparliament.ca
 * Auth: none (public API, no key required)
 * Docs: https://api.openparliament.ca/
 * Source: github.com/michaelmulley/openparliament
 * Category: government
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface OpenParliamentCaConfig {
  baseUrl?: string;
}

export class OpenParliamentCaMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: OpenParliamentCaConfig) {
    super();
    if (config === null) { throw new Error('OpenParliamentCaMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl || 'https://api.openparliament.ca';
  }

  static catalog() {
    return {
      name: 'openparliament-ca',
      displayName: 'OpenParliament.ca — Parliament of Canada',
      version: '1.0.0',
      category: 'government' as const,
      keywords: [
        'canada', 'parliament', 'canadian', 'mp', 'member of parliament',
        'hansard', 'debates', 'speeches', 'bills', 'legislation', 'votes',
        'politicians', 'committees', 'house of commons', 'senate',
        'civic tech', 'openparliament', 'federal', 'riding', 'party',
        'liberal', 'conservative', 'ndp', 'bloc', 'green',
      ],
      toolNames: [
        'search_debates',
        'list_bills',
        'get_bill',
        'list_votes',
        'list_politicians',
        'get_politician',
        'list_committees',
        'list_committee_meetings',
      ],
      description: 'OpenParliament.ca API: search Hansard debates, list and retrieve Canadian bills, recorded votes, MP profiles, and House committee meetings — no authentication required.',
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
        name: 'search_debates',
        description: 'Search Hansard contributions (debates) in the Parliament of Canada. Returns speeches matching the query, optionally filtered by date range, politician slug, or party.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Full-text search query (e.g. "carbon tax")' },
            date_from: { type: 'string', description: 'Start date filter in YYYY-MM-DD format' },
            date_to: { type: 'string', description: 'End date filter in YYYY-MM-DD format' },
            politician: { type: 'string', description: 'Politician slug to filter by (e.g. "chrystia-freeland")' },
            party: { type: 'string', description: 'Party slug to filter by (e.g. "liberal", "conservative", "ndp")' },
            limit: { type: 'number', description: 'Number of results to return (1–100, default 20)' },
            offset: { type: 'number', description: '0-based offset for pagination' },
          },
          required: ['query'],
        },
      },
      {
        name: 'list_bills',
        description: 'List bills introduced in the Parliament of Canada, optionally filtered by session, sponsoring MP, or status.',
        inputSchema: {
          type: 'object',
          properties: {
            session: { type: 'string', description: 'Parliament-session string (e.g. "44-1")' },
            sponsor: { type: 'string', description: 'Sponsor politician slug' },
            status: { type: 'string', description: 'Bill status filter' },
            limit: { type: 'number', description: 'Number of results to return (1–100, default 20)' },
            offset: { type: 'number', description: '0-based offset for pagination' },
          },
        },
      },
      {
        name: 'get_bill',
        description: 'Retrieve full detail for a specific bill by parliament session and bill number.',
        inputSchema: {
          type: 'object',
          properties: {
            session: { type: 'string', description: 'Parliament-session string (e.g. "44-1")' },
            number: { type: 'string', description: 'Bill number (e.g. "C-318")' },
          },
          required: ['session', 'number'],
        },
      },
      {
        name: 'list_votes',
        description: 'List recorded votes in the Parliament of Canada, optionally filtered by session.',
        inputSchema: {
          type: 'object',
          properties: {
            session: { type: 'string', description: 'Parliament-session string (e.g. "44-1")' },
            limit: { type: 'number', description: 'Number of results to return (1–100, default 20)' },
            offset: { type: 'number', description: '0-based offset for pagination' },
          },
        },
      },
      {
        name: 'list_politicians',
        description: 'List current and historic Members of Parliament, optionally filtered by party, province, or name fragment.',
        inputSchema: {
          type: 'object',
          properties: {
            current: { type: 'boolean', description: 'When true (default), return only currently sitting MPs' },
            party: { type: 'string', description: 'Party slug (e.g. "liberal", "conservative", "ndp")' },
            province: { type: 'string', description: 'Province code (e.g. "ON", "BC", "QC")' },
            name: { type: 'string', description: 'Name fragment to search for' },
            limit: { type: 'number', description: 'Number of results to return (1–100, default 20)' },
            offset: { type: 'number', description: '0-based offset for pagination' },
          },
        },
      },
      {
        name: 'get_politician',
        description: 'Retrieve a full profile for a Member of Parliament by their slug.',
        inputSchema: {
          type: 'object',
          properties: {
            slug: { type: 'string', description: 'Politician slug (e.g. "chrystia-freeland", "mark-carney")' },
          },
          required: ['slug'],
        },
      },
      {
        name: 'list_committees',
        description: 'List House of Commons committees, optionally filtered by session.',
        inputSchema: {
          type: 'object',
          properties: {
            session: { type: 'string', description: 'Parliament-session string (e.g. "44-1")' },
            limit: { type: 'number', description: 'Number of results to return (1–100, default 20)' },
            offset: { type: 'number', description: '0-based offset for pagination' },
          },
        },
      },
      {
        name: 'list_committee_meetings',
        description: 'List House of Commons committee meetings including witnesses and evidence, optionally filtered by committee slug or date range.',
        inputSchema: {
          type: 'object',
          properties: {
            committee_slug: { type: 'string', description: 'Committee slug to filter by' },
            date_from: { type: 'string', description: 'Start date filter in YYYY-MM-DD format' },
            date_to: { type: 'string', description: 'End date filter in YYYY-MM-DD format' },
            limit: { type: 'number', description: 'Number of results to return (1–100, default 20)' },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_debates':        return this.searchDebates(args);
        case 'list_bills':            return this.listBills(args);
        case 'get_bill':              return this.getBill(args);
        case 'list_votes':            return this.listVotes(args);
        case 'list_politicians':      return this.listPoliticians(args);
        case 'get_politician':        return this.getPolitician(args);
        case 'list_committees':       return this.listCommittees(args);
        case 'list_committee_meetings': return this.listCommitteeMeetings(args);
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

  private async get(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': 'epicai-chariot/1.0 (+https://epicai.com)',
      },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'OpenParliament.ca: record not found (404)' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private clampLimit(args: Record<string, unknown>, def = 20): number {
    return Math.min(100, Math.max(1, (args.limit as number) ?? def));
  }

  private clampOffset(args: Record<string, unknown>): number {
    return Math.max(0, (args.offset as number) ?? 0);
  }

  private async searchDebates(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query;
    if (typeof query !== 'string' || !query.trim()) {
      return { content: [{ type: 'text', text: 'Required argument "query" is missing or empty.' }], isError: true };
    }
    const params = new URLSearchParams({
      q: query,
      format: 'json',
      limit: String(this.clampLimit(args)),
      offset: String(this.clampOffset(args)),
    });
    if (args.date_from) params.set('date__gte', String(args.date_from));
    if (args.date_to)   params.set('date__lte', String(args.date_to));
    if (args.politician) params.set('politician', String(args.politician));
    if (args.party)     params.set('party', String(args.party));
    return this.get(`/speeches/?${params}`);
  }

  private async listBills(args: Record<string, unknown>): Promise<ToolResult> {
    return this.get(`/bills/${this.appendParams(args, ['session', 'sponsor', 'status'])}`);
  }

  private async getBill(args: Record<string, unknown>): Promise<ToolResult> {
    const session = args.session;
    const number = args.number;
    if (typeof session !== 'string' || !session.trim()) {
      return { content: [{ type: 'text', text: 'Required argument "session" is missing or empty (e.g. "44-1").' }], isError: true };
    }
    if (typeof number !== 'string' || !number.trim()) {
      return { content: [{ type: 'text', text: 'Required argument "number" is missing or empty (e.g. "C-318").' }], isError: true };
    }
    return this.get(`/bills/${encodeURIComponent(session)}/${encodeURIComponent(number)}/?format=json`);
  }

  private async listVotes(args: Record<string, unknown>): Promise<ToolResult> {
    return this.get(`/votes/${this.appendParams(args, ['session'])}`);
  }

  private async listPoliticians(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      format: 'json',
      limit: String(this.clampLimit(args)),
      offset: String(this.clampOffset(args)),
    });
    if (args.party)    params.set('party', String(args.party));
    if (args.province) params.set('province', String(args.province));
    if (args.name)     params.set('q', String(args.name));
    // default to current=true unless caller explicitly passes false
    if (args.current !== false) {
      params.set('current', 'true');
    }
    return this.get(`/politicians/?${params}`);
  }

  private async getPolitician(args: Record<string, unknown>): Promise<ToolResult> {
    const slug = args.slug;
    if (typeof slug !== 'string' || !slug.trim()) {
      return { content: [{ type: 'text', text: 'Required argument "slug" is missing or empty (e.g. "chrystia-freeland").' }], isError: true };
    }
    return this.get(`/politicians/${encodeURIComponent(slug)}/?format=json`);
  }

  private async listCommittees(args: Record<string, unknown>): Promise<ToolResult> {
    return this.get(`/committees/${this.appendParams(args, ['session'])}`);
  }

  private async listCommitteeMeetings(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      format: 'json',
      limit: String(this.clampLimit(args)),
    });
    if (args.committee_slug) params.set('committee', String(args.committee_slug));
    if (args.date_from)      params.set('date__gte', String(args.date_from));
    if (args.date_to)        params.set('date__lte', String(args.date_to));
    return this.get(`/committees/meetings/?${params}`);
  }

  /**
   * Build a query-string suffix with format=json, limit, offset, and any
   * extra named keys that are present and non-empty in args.
   */
  private appendParams(args: Record<string, unknown>, keys: string[]): string {
    const params = new URLSearchParams({
      format: 'json',
      limit: String(this.clampLimit(args)),
      offset: String(this.clampOffset(args)),
    });
    for (const k of keys) {
      const v = args[k];
      if (v !== undefined && v !== null && String(v).trim()) {
        params.set(k, String(v));
      }
    }
    return `?${params}`;
  }
}
