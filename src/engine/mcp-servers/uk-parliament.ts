/**
 * UK Parliament MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream APIs (no auth required):
 *  - Members:  https://members-api.parliament.uk/api
 *  - Bills:    https://bills-api.parliament.uk/api/v1
 *  - Hansard:  https://hansard-api.parliament.uk
 *
 * Docs: https://developer.parliament.uk/
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const MEMBERS_BASE  = 'https://members-api.parliament.uk/api';
const BILLS_BASE    = 'https://bills-api.parliament.uk/api/v1';
const HANSARD_BASE  = 'https://hansard-api.parliament.uk';
const COMMONS_VOTES = 'https://commonsvotes-api.parliament.uk/data';
const LORDS_VOTES   = 'https://lordsvotes-api.parliament.uk/data';

const HOUSES_DESC = '1 = Commons, 2 = Lords';

export class UKParliamentMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'uk-parliament',
      displayName: 'UK Parliament',
      version: '1.0.0',
      category: 'government',
      keywords: [
        'uk parliament', 'parliament', 'mps', 'lords', 'bills', 'hansard',
        'house of commons', 'house of lords', 'legislation', 'debates',
        'divisions', 'votes', 'members', 'westminster', 'uk government',
        'british politics', 'hansard contributions',
      ],
      toolNames: [
        'search_members',
        'get_member',
        'search_bills',
        'get_bill',
        'bill_stages',
        'search_hansard',
        'recent_divisions',
      ],
      description: 'UK Parliament APIs: search MPs and Lords, retrieve bill details and legislative stages, search Hansard debate contributions, and view recent division (vote) records — all via the official Parliament open data endpoints.',
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
        name: 'search_members',
        description: 'Search MPs and Lords by name, party, location, or house.',
        inputSchema: {
          type: 'object',
          properties: {
            name:       { type: 'string',  description: 'Search across name fields' },
            location:   { type: 'string',  description: 'Postcode or constituency name' },
            party:      { type: 'string',  description: 'Party name' },
            house:      { type: 'number',  description: HOUSES_DESC },
            is_current: { type: 'boolean', description: 'Only currently-sitting members (default true)' },
            take:       { type: 'number',  description: '1–20 (default 20)' },
            skip:       { type: 'number',  description: '0-based offset' },
          },
        },
      },
      {
        name: 'get_member',
        description: 'Retrieve member detail by Parliament member id.',
        inputSchema: {
          type: 'object',
          properties: {
            id:       { type: 'number', description: 'Parliament member id' },
            includes: { type: 'string', description: 'Comma-separated sub-resources: Posts | Biography | Contact | Synopsis' },
          },
          required: ['id'],
        },
      },
      {
        name: 'search_bills',
        description: 'Search bills by title, session, stage, or sponsoring member.',
        inputSchema: {
          type: 'object',
          properties: {
            query:         { type: 'string', description: 'Search bill title and short title' },
            session:       { type: 'number', description: 'Session id (numeric)' },
            stage:         { type: 'number', description: 'Stage id (1=intro, 2=first reading, etc.)' },
            member_id:     { type: 'number', description: 'Sponsoring member id' },
            current_house: { type: 'number', description: HOUSES_DESC },
            sort: {
              type: 'string',
              description: 'TitleAscending | TitleDescending | DateUpdatedAscending | DateUpdatedDescending',
            },
            take: { type: 'number', description: '1–50 (default 20)' },
            skip: { type: 'number', description: '0-based offset' },
          },
        },
      },
      {
        name: 'get_bill',
        description: 'Retrieve bill detail by bill id.',
        inputSchema: {
          type: 'object',
          properties: {
            bill_id: { type: 'number', description: 'Bill id' },
          },
          required: ['bill_id'],
        },
      },
      {
        name: 'bill_stages',
        description: 'Retrieve all legislative stages of a bill (introduction, readings, committee, royal assent).',
        inputSchema: {
          type: 'object',
          properties: {
            bill_id: { type: 'number', description: 'Bill id' },
          },
          required: ['bill_id'],
        },
      },
      {
        name: 'search_hansard',
        description: 'Search spoken debate contributions in Hansard (full-text search).',
        inputSchema: {
          type: 'object',
          properties: {
            query:     { type: 'string', description: 'Full-text query (required)' },
            house:     { type: 'string', description: 'Commons | Lords' },
            date_from: { type: 'string', description: 'Start date YYYY-MM-DD' },
            date_to:   { type: 'string', description: 'End date YYYY-MM-DD' },
            member_id: { type: 'number', description: 'Filter by contributing member id' },
            take:      { type: 'number', description: '1–20 (default 20)' },
            skip:      { type: 'number', description: '0-based offset' },
          },
          required: ['query'],
        },
      },
      {
        name: 'recent_divisions',
        description: 'List recent recorded votes (divisions) from Hansard.',
        inputSchema: {
          type: 'object',
          properties: {
            house:     { type: 'string', description: 'Commons | Lords' },
            date_from: { type: 'string', description: 'Start date YYYY-MM-DD' },
            take:      { type: 'number', description: '1–25 (default 25)' },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_members':   return this.searchMembers(args);
        case 'get_member':       return this.getMember(args);
        case 'search_bills':     return this.searchBills(args);
        case 'get_bill':         return this.getBill(args);
        case 'bill_stages':      return this.getBillStages(args);
        case 'search_hansard':   return this.searchHansard(args);
        case 'recent_divisions': return this.recentDivisions(args);
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

  // ── Private helpers ──────────────────────────────────────────────────────────

  /**
   * Internal fetch helper — returns the raw parsed JSON value (no truncation)
   * so callers that need to re-parse or merge the result can do so without
   * hitting a SyntaxError on a truncated string (PATTERN-A bug).
   * Throws on HTTP error.
   */
  private async getJson(url: string): Promise<unknown> {
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': 'epic-ai-chariot/1.0.0 (https://epic-ai.com)',
      },
    });
    if (response.status === 404) {
      throw new Error('UK Parliament: not found (HTTP 404)');
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`UK Parliament API error: ${response.status} ${errText.slice(0, 200)}`);
    }
    return response.json();
  }

  /**
   * Public fetch helper — wraps getJson() and truncates the result to the
   * 10 KB tool-result limit. Used for all tools that return a single
   * upstream response as their final output.
   */
  private async get(url: string): Promise<ToolResult> {
    try {
      const data = await this.getJson(url);
      return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
    } catch (err) {
      return {
        content: [{ type: 'text', text: err instanceof Error ? err.message : String(err) }],
        isError: true,
      };
    }
  }

  private requireNum(args: Record<string, unknown>, key: string): number {
    const v = args[key];
    if (typeof v !== 'number' || !Number.isFinite(v)) {
      throw new Error(`Required argument "${key}" must be a finite number.`);
    }
    return v;
  }

  private requireStr(args: Record<string, unknown>, key: string): string {
    const v = args[key];
    if (typeof v !== 'string' || v.trim() === '') {
      throw new Error(`Required argument "${key}" must be a non-empty string.`);
    }
    return v;
  }

  private async searchMembers(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      take: String(Math.min(20, Math.max(1, (args.take as number) ?? 20))),
      skip: String(Math.max(0, (args.skip as number) ?? 0)),
    });
    if (args.name)       params.set('Name',            String(args.name));
    if (args.location)   params.set('Location',        String(args.location));
    if (args.party)      params.set('Party',           String(args.party));
    if (args.house !== undefined) params.set('House', String(args.house));
    params.set('IsCurrentMember', String(args.is_current !== false));
    return this.get(`${MEMBERS_BASE}/Members/Search?${params}`);
  }

  private async getMember(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireNum(args, 'id');
    const base = `${MEMBERS_BASE}/Members/${id}`;
    const includes = typeof args.includes === 'string' ? args.includes.trim() : '';
    if (!includes) return this.get(base);

    // Fetch main record plus requested sub-resources in parallel.
    // Use getJson() so we always have the full untruncated object to merge;
    // truncation happens once on the combined output (PATTERN-A fix).
    const subKeys = includes.split(',').map((s) => s.trim()).filter(Boolean);
    let mainData: unknown;
    try {
      mainData = await this.getJson(base);
    } catch (err) {
      return {
        content: [{ type: 'text', text: err instanceof Error ? err.message : String(err) }],
        isError: true,
      };
    }
    const extras: Record<string, unknown> = {};
    const subResults = await Promise.allSettled(
      subKeys.map((k) => this.getJson(`${base}/${encodeURIComponent(k)}`)),
    );
    for (let i = 0; i < subKeys.length; i++) {
      const r = subResults[i];
      if (r.status === 'fulfilled') {
        extras[subKeys[i]] = r.value;
      } else {
        extras[subKeys[i]] = { error: r.reason instanceof Error ? r.reason.message : String(r.reason) };
      }
    }
    return { content: [{ type: 'text', text: this.truncate({ member: mainData, includes: extras }) }], isError: false };
  }

  private async searchBills(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      Sort: String(args.sort ?? 'DateUpdatedDescending'),
      Take: String(Math.min(50, Math.max(1, (args.take as number) ?? 20))),
      Skip: String(Math.max(0, (args.skip as number) ?? 0)),
    });
    if (args.query)         params.set('SearchTerm',   String(args.query));
    if (args.session !== undefined) params.set('Session', String(args.session));
    if (args.stage   !== undefined) params.set('CurrentStage', String(args.stage));
    if (args.member_id !== undefined) params.set('MemberId', String(args.member_id));
    if (args.current_house !== undefined) params.set('CurrentHouse', String(args.current_house));
    return this.get(`${BILLS_BASE}/Bills?${params}`);
  }

  private async getBill(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireNum(args, 'bill_id');
    return this.get(`${BILLS_BASE}/Bills/${id}`);
  }

  private async getBillStages(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireNum(args, 'bill_id');
    return this.get(`${BILLS_BASE}/Bills/${id}/Stages`);
  }

  private async searchHansard(args: Record<string, unknown>): Promise<ToolResult> {
    const query = this.requireStr(args, 'query');
    const params = new URLSearchParams({
      searchTerm: query,
      take: String(Math.min(20, Math.max(1, (args.take as number) ?? 20))),
      skip: String(Math.max(0, (args.skip as number) ?? 0)),
    });
    if (args.house)     params.set('house',      String(args.house));
    if (args.date_from) params.set('startDate',  String(args.date_from));
    if (args.date_to)   params.set('endDate',    String(args.date_to));
    if (args.member_id !== undefined) params.set('memberId', String(args.member_id));
    return this.get(`${HANSARD_BASE}/search/contributions/spoken?${params}`);
  }

  private async recentDivisions(args: Record<string, unknown>): Promise<ToolResult> {
    const take      = Math.min(25, Math.max(1, (args.take as number) ?? 25));
    const houseArg  = typeof args.house === 'string' ? args.house.trim().toLowerCase() : '';
    const dateFrom  = typeof args.date_from === 'string' ? args.date_from.trim() : '';

    // Build per-house query strings.
    // Commons API uses queryParameters.* prefix; Lords API uses bare params.
    const commonsParams = new URLSearchParams({ 'queryParameters.take': String(take) });
    const lordsParams   = new URLSearchParams({ take: String(take) });
    if (dateFrom) {
      commonsParams.set('queryParameters.startDateIso8601', dateFrom);
      lordsParams.set('startDate', dateFrom);
    }

    const fetchCommons = () => this.getJson(`${COMMONS_VOTES}/divisions.json/search?${commonsParams}`);
    const fetchLords   = () => this.getJson(`${LORDS_VOTES}/divisions/search?${lordsParams}`);

    // Route by house.  When unspecified fetch both and merge (PATTERN-A fix:
    // use getJson() to get untruncated objects; only truncate the final output).
    if (houseArg === 'commons') {
      try {
        const data = await fetchCommons();
        return { content: [{ type: 'text', text: this.truncate({ house: 'Commons', divisions: data }) }], isError: false };
      } catch (err) {
        return { content: [{ type: 'text', text: err instanceof Error ? err.message : String(err) }], isError: true };
      }
    }

    if (houseArg === 'lords') {
      try {
        const data = await fetchLords();
        return { content: [{ type: 'text', text: this.truncate({ house: 'Lords', divisions: data }) }], isError: false };
      } catch (err) {
        return { content: [{ type: 'text', text: err instanceof Error ? err.message : String(err) }], isError: true };
      }
    }

    // Both houses — fetch in parallel, merge, truncate once.
    const [commonsResult, lordsResult] = await Promise.allSettled([fetchCommons(), fetchLords()]);
    const merged: Record<string, unknown> = {};
    if (commonsResult.status === 'fulfilled') {
      merged['Commons'] = commonsResult.value;
    } else {
      merged['Commons'] = { error: commonsResult.reason instanceof Error ? commonsResult.reason.message : String(commonsResult.reason) };
    }
    if (lordsResult.status === 'fulfilled') {
      merged['Lords'] = lordsResult.value;
    } else {
      merged['Lords'] = { error: lordsResult.reason instanceof Error ? lordsResult.reason.message : String(lordsResult.reason) };
    }
    return { content: [{ type: 'text', text: this.truncate(merged) }], isError: false };
  }
}
