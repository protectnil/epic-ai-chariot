/**
 * NSF Awards MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://www.research.gov/common/webapi/awardapisearch-v1.htm
// Base URL: https://api.nsf.gov/services/v1/awards
// Auth: none (public, no-auth-verified)
// Category: research
// Rate limits: None documented; public API — be respectful
//
// Covers ~$10B/yr of NSF-funded research across physical sciences,
// engineering, CS, math, education, and social sciences.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.nsf.gov/services/v1/awards';

const SUMMARY_FIELDS = [
  'id',
  'title',
  'awardeeName',
  'awardeeCity',
  'awardeeStateCode',
  'awardeeCountryCode',
  'piFirstName',
  'piLastName',
  'pdPIName',
  'fundsObligatedAmt',
  'estimatedTotalAmt',
  'startDate',
  'expDate',
  'date',
  'agency',
  'fundProgramName',
  'cfdaNumber',
  'transType',
];

const FULL_FIELDS = [
  ...SUMMARY_FIELDS,
  'abstract',
  'projectOutComesReport',
  'piEmail',
  'coPDPI',
  'perfLocation',
  'perfCity',
  'perfStateCode',
  'perfZipCode',
  'awardeeAddress',
  'publicationResearch',
  'publicationConference',
];

export class NsfAwardsMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('NsfAwardsMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'nsf-awards',
      displayName: 'NSF Awards',
      version: '1.0.0',
      category: 'research',
      keywords: [
        'nsf', 'national science foundation', 'awards', 'grants', 'funding',
        'research', 'science', 'engineering', 'education', 'pi', 'principal investigator',
        'awardee', 'institution', 'program', 'abstract', 'outcomes', 'federal grants',
        'stem', 'cs', 'math', 'physics', 'social science',
      ],
      toolNames: ['search_awards', 'get_award'],
      description: 'NSF Awards: search and retrieve National Science Foundation grant awards covering ~$10B/yr of US research funding across physical sciences, engineering, CS, math, education, and social sciences — free public API, no authentication required.',
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
        name: 'search_awards',
        description:
          'Search NSF awards. Filter by keyword (matches title/abstract), PI name, awardee institution, NSF program, date range, US state, or country. Returns title, PI, awardee, amount, dates, program. Use get_award for full abstract + outcomes report.',
        inputSchema: {
          type: 'object',
          properties: {
            keyword: { type: 'string', description: 'Search term (title + abstract)' },
            pi_name: { type: 'string', description: 'PI full or last name' },
            awardee: { type: 'string', description: 'Awardee institution name' },
            program: { type: 'string', description: 'NSF program name (e.g., "Algorithms in the Field")' },
            state: { type: 'string', description: 'Awardee US state code (e.g., "CA")' },
            country: { type: 'string', description: 'Awardee country code (e.g., "US")' },
            date_start: { type: 'string', description: 'Award start date >= MM/DD/YYYY' },
            date_end: { type: 'string', description: 'Award start date <= MM/DD/YYYY' },
            limit: { type: 'number', description: 'Results per page (1-25, default 25 — NSF max)' },
            offset: { type: 'number', description: 'Pagination offset (default 1)' },
          },
          required: [],
        },
      },
      {
        name: 'get_award',
        description:
          'Fetch a single NSF award by ID. Returns full abstract, project outcomes report (if completed), and detailed PI/awardee info.',
        inputSchema: {
          type: 'object',
          properties: {
            award_id: { type: 'string', description: 'NSF award ID (numeric string)' },
          },
          required: ['award_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_awards': return this.searchAwards(args);
        case 'get_award':     return this.getAward(args);
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

  private async searchAwards(args: Record<string, unknown>): Promise<ToolResult> {
    const limit = typeof args.limit === 'number' ? Math.min(25, Math.max(1, args.limit)) : 25;
    const offset = typeof args.offset === 'number' ? args.offset : 1;

    const params = new URLSearchParams({
      printFields: SUMMARY_FIELDS.join(','),
      rpp: String(limit),
      offset: String(offset),
    });

    if (args.keyword)    params.set('keyword',          String(args.keyword));
    if (args.pi_name)    params.set('pdPIName',          String(args.pi_name));
    if (args.awardee)    params.set('awardeeName',       String(args.awardee));
    if (args.program)    params.set('fundProgramName',   String(args.program));
    if (args.state)      params.set('awardeeStateCode',  String(args.state).toUpperCase());
    if (args.country)    params.set('awardeeCountryCode', String(args.country).toUpperCase());
    if (args.date_start) params.set('dateStart',         String(args.date_start));
    if (args.date_end)   params.set('dateEnd',           String(args.date_end));

    const url = `${this.baseUrl}.json?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NSF API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      response?: { award?: AwardRecord[]; serviceNotification?: unknown[] };
    };
    const awards = data.response?.award ?? [];

    const result = {
      returned: awards.length,
      note: 'NSF API caps rpp at 25; use offset to paginate.',
      awards: awards.map((a) => this.normalizeAward(a, false)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getAward(args: Record<string, unknown>): Promise<ToolResult> {
    const awardId = args.award_id;
    if (!awardId || typeof awardId !== 'string') {
      return { content: [{ type: 'text', text: 'award_id is required and must be a string' }], isError: true };
    }

    const params = new URLSearchParams({
      id: awardId,
      printFields: FULL_FIELDS.join(','),
    });

    const url = `${this.baseUrl}.json?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NSF API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as { response?: { award?: AwardRecord[] } };
    const a = data.response?.award?.[0];
    if (!a) {
      return {
        content: [{ type: 'text', text: `No NSF award found for id ${awardId}` }],
        isError: true,
      };
    }

    return { content: [{ type: 'text', text: this.truncate(this.normalizeAward(a, true)) }], isError: false };
  }

  private normalizeAward(a: AwardRecord, full: boolean): Record<string, unknown> {
    const out: Record<string, unknown> = {
      award_id:         a.id ?? null,
      title:            a.title ?? null,
      pi:               a.pdPIName ?? ([a.piFirstName, a.piLastName].filter(Boolean).join(' ') || null),
      awardee:          a.awardeeName ?? null,
      awardee_city:     a.awardeeCity ?? null,
      awardee_state:    a.awardeeStateCode ?? null,
      awardee_country:  a.awardeeCountryCode ?? null,
      funds_obligated:  a.fundsObligatedAmt  ? Number(a.fundsObligatedAmt)  : null,
      estimated_total:  a.estimatedTotalAmt  ? Number(a.estimatedTotalAmt)  : null,
      start_date:       a.startDate  ?? null,
      expiration_date:  a.expDate    ?? null,
      award_date:       a.date       ?? null,
      agency:           a.agency     ?? null,
      program:          a.fundProgramName ?? null,
      cfda_number:      a.cfdaNumber ?? null,
      transaction_type: a.transType  ?? null,
      nsf_url:          a.id ? `https://www.nsf.gov/awardsearch/showAward?AWD_ID=${a.id}` : null,
    };

    if (full) {
      out.pi_email             = a.piEmail ?? null;
      out.co_pi                = a.coPDPI ?? [];
      out.performance_location = a.perfLocation ?? null;
      out.performance_city     = a.perfCity ?? null;
      out.performance_state    = a.perfStateCode ?? null;
      out.performance_zip      = a.perfZipCode ?? null;
      out.awardee_address      = a.awardeeAddress ?? null;
      out.abstract             = a.abstract ?? null;
      out.outcomes_report      = a.projectOutComesReport ?? null;
      out.publications         = [...(a.publicationResearch ?? []), ...(a.publicationConference ?? [])];
    }

    return out;
  }
}

// ── Upstream type shapes ────────────────────────────────────────────────────

interface AwardRecord {
  id?: string;
  title?: string;
  awardeeName?: string;
  awardeeCity?: string;
  awardeeStateCode?: string;
  awardeeCountryCode?: string;
  awardeeAddress?: string;
  pdPIName?: string;
  piFirstName?: string;
  piLastName?: string;
  piEmail?: string;
  coPDPI?: string[];
  fundsObligatedAmt?: string;
  estimatedTotalAmt?: string;
  startDate?: string;
  expDate?: string;
  date?: string;
  agency?: string;
  fundProgramName?: string;
  cfdaNumber?: string;
  transType?: string;
  abstract?: string;
  projectOutComesReport?: string;
  perfLocation?: string;
  perfCity?: string;
  perfStateCode?: string;
  perfZipCode?: string;
  publicationResearch?: string[];
  publicationConference?: string[];
}
