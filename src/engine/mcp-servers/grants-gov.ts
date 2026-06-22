/**
 * Grants.gov MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

//
// Base URL: https://api.grants.gov/v1/api
// Auth: None required — Grants.gov API is a free, unauthenticated federal service.
// Docs: https://www.grants.gov/web/grants/s2s/grantor/schemas/grants-gov-search2.html
// Category: government
// Rate limits: Fair-use; no published hard limit.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface GrantsGovConfig {
  /** Optional base URL override (default: https://api.grants.gov/v1/api) */
  baseUrl?: string;
}

export class GrantsGovMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config: GrantsGovConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Grants.gov: configuration object is required');
    }
    this.baseUrl = config.baseUrl ?? 'https://api.grants.gov/v1/api';
  }

  static catalog() {
    return {
      name: 'grants-gov',
      displayName: 'Grants.gov — Federal Funding Opportunities',
      version: '1.0.0',
      category: 'government',
      keywords: [
        'grants', 'grants.gov', 'federal grants', 'funding', 'opportunities',
        'government funding', 'federal funding', 'cfda', 'aln', 'assistance listing',
        'research funding', 'nonprofit', 'agency', 'EPA', 'USDA', 'NIH',
        'forecasted', 'posted', 'closed', 'archived', 'synopsis',
      ],
      toolNames: ['search_opportunities', 'get_opportunity'],
      description: 'Grants.gov API v1: search currently-open and forecasted federal funding opportunities, and fetch full opportunity details including synopsis, eligibility, award amounts, contacts, and attachments — free and unauthenticated.',
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
        name: 'search_opportunities',
        description:
          'Search Grants.gov for currently-open or recently-closed federal funding opportunities. Filter by keyword, opportunity status, agency code, funding category, or assistance listing number (ALN/CFDA). Returns opportunity number, title, agency, open/close dates, and assistance listing numbers.',
        inputSchema: {
          type: 'object',
          properties: {
            keyword: {
              type: 'string',
              description: 'Full-text query',
            },
            status: {
              type: 'string',
              description: 'forecasted | posted | closed | archived (default posted; use a pipe to combine, e.g. "posted|forecasted")',
            },
            agencies: {
              type: 'string',
              description: 'Comma-separated agency codes (e.g., "EPA,USDA,NIH")',
            },
            funding_categories: {
              type: 'string',
              description: 'Comma-separated category codes (e.g., "ED" education, "ENV" environment, "ST" science)',
            },
            aln: {
              type: 'string',
              description: 'Assistance Listing Number / CFDA number (e.g., "10.001")',
            },
            limit: {
              type: 'number',
              description: 'Rows per page (1-1000, default 25)',
            },
            offset: {
              type: 'number',
              description: '0-based start record (default 0)',
            },
          },
        },
      },
      {
        name: 'get_opportunity',
        description:
          'Fetch full details for a Grants.gov opportunity by its numeric ID. Returns synopsis text, eligibility, award ceiling/floor, attachments, contact info, and version history.',
        inputSchema: {
          type: 'object',
          properties: {
            opportunity_id: {
              type: 'number',
              description: 'Numeric opportunity ID (returned by search_opportunities as "id")',
            },
          },
          required: ['opportunity_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_opportunities': return this.searchOpportunities(args);
        case 'get_opportunity':      return this.getOpportunity(args);
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

  private async grantsPost<T>(path: string, body: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`Grants.gov error: ${response.status} ${errText.slice(0, 200)}`);
    }
    return response.json() as Promise<T>;
  }

  private async searchOpportunities(args: Record<string, unknown>): Promise<ToolResult> {
    const body: Record<string, unknown> = {
      rows: Math.min(1000, Math.max(1, (args.limit as number) ?? 25)),
      startRecordNum: (args.offset as number) ?? 0,
      sortBy: 'openDate|desc',
      oppStatuses: (args.status as string) ?? 'posted',
    };
    if (args.keyword) body.keyword = String(args.keyword);
    if (args.agencies) body.agencies = String(args.agencies);
    if (args.funding_categories) body.fundingCategories = String(args.funding_categories);
    if (args.aln) body.cfda = String(args.aln);

    const data = await this.grantsPost<{
      errorcode?: number;
      msg?: string;
      data?: {
        hitCount?: number;
        oppHits?: SearchHit[];
      };
    }>('/search2', body);

    if (data.errorcode && data.errorcode !== 0) {
      return {
        content: [{ type: 'text', text: `Grants.gov error: ${data.msg ?? 'unknown error'}` }],
        isError: true,
      };
    }

    const hits = data.data?.oppHits ?? [];
    const result = {
      total: data.data?.hitCount ?? 0,
      returned: hits.length,
      opportunities: hits.map(normalizeHit),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getOpportunity(args: Record<string, unknown>): Promise<ToolResult> {
    const opportunityId = args.opportunity_id as number;
    if (typeof opportunityId !== 'number' || !Number.isFinite(opportunityId)) {
      return {
        content: [{ type: 'text', text: 'get_opportunity: opportunity_id must be a finite number' }],
        isError: true,
      };
    }

    const data = await this.grantsPost<{
      errorcode?: number;
      msg?: string;
      data?: OpportunityDetail;
    }>('/fetchOpportunity', { opportunityId });

    if (data.errorcode && data.errorcode !== 0) {
      return {
        content: [{ type: 'text', text: `Grants.gov error: ${data.msg ?? `no opportunity ${opportunityId}`}` }],
        isError: true,
      };
    }
    if (!data.data) {
      return {
        content: [{ type: 'text', text: `Grants.gov: no data for opportunity ${opportunityId}` }],
        isError: true,
      };
    }
    return { content: [{ type: 'text', text: this.truncate(normalizeDetail(data.data)) }], isError: false };
  }
}

// ── Data-shape helpers (module-private) ────────────────────────────────────

interface SearchHit {
  id?: string;
  number?: string;
  title?: string;
  agencyCode?: string;
  agencyName?: string;
  agency?: string;
  openDate?: string;
  closeDate?: string;
  oppStatus?: string;
  docType?: string;
  alnist?: { alnis?: string }[];
}

function normalizeHit(h: SearchHit): Record<string, unknown> {
  return {
    id: h.id ? Number(h.id) : null,
    number: h.number ?? null,
    title: h.title ?? null,
    agency_code: h.agencyCode ?? null,
    agency: h.agencyName ?? h.agency ?? null,
    open_date: h.openDate ?? null,
    close_date: h.closeDate ?? null,
    status: h.oppStatus ?? null,
    doc_type: h.docType ?? null,
    assistance_listing_numbers: (h.alnist ?? []).map((a) => a.alnis).filter(Boolean),
    grants_gov_url: h.id ? `https://www.grants.gov/search-results-detail/${h.id}` : null,
  };
}

interface OpportunityDetail {
  id?: number;
  opportunityNumber?: string;
  opportunityTitle?: string;
  agencyCode?: string;
  agencyName?: string;
  topAgencyDetails?: { agencyCode?: string; agencyName?: string };
  synopsis?: {
    synopsisDesc?: string;
    awardCeiling?: string;
    awardFloor?: string;
    estimatedFunding?: string;
    awardNumber?: string;
    fundingInstrument?: { fundingInstrumentName?: string }[];
    fundingActivityCategories?: { categoryName?: string }[];
    applicantTypes?: { applicantTypeName?: string }[];
    eligibilityDesc?: string;
    agencyContactName?: string;
    agencyContactEmail?: string;
    agencyContactPhone?: string;
    postingDate?: string;
    responseDate?: string;
    closingDateDesc?: string;
    archiveDate?: string;
  };
  cfdas?: { cfdaNumber?: string; programTitle?: string }[];
  synopsisAttachmentFolders?: {
    folderName?: string;
    attachments?: { fileName?: string; downloadURL?: string }[];
  }[];
}

function normalizeDetail(d: OpportunityDetail): Record<string, unknown> {
  const s = d.synopsis ?? {};
  return {
    id: d.id ?? null,
    number: d.opportunityNumber ?? null,
    title: d.opportunityTitle ?? null,
    agency_code: d.agencyCode ?? d.topAgencyDetails?.agencyCode ?? null,
    agency: d.agencyName ?? d.topAgencyDetails?.agencyName ?? null,
    synopsis: s.synopsisDesc ?? null,
    eligibility: s.eligibilityDesc ?? null,
    award_ceiling: s.awardCeiling ? Number(s.awardCeiling) : null,
    award_floor: s.awardFloor ? Number(s.awardFloor) : null,
    estimated_funding: s.estimatedFunding ? Number(s.estimatedFunding) : null,
    expected_awards: s.awardNumber ? Number(s.awardNumber) : null,
    funding_instruments: (s.fundingInstrument ?? []).map((f) => f.fundingInstrumentName).filter(Boolean),
    funding_categories: (s.fundingActivityCategories ?? []).map((c) => c.categoryName).filter(Boolean),
    applicant_types: (s.applicantTypes ?? []).map((a) => a.applicantTypeName).filter(Boolean),
    cfdas: (d.cfdas ?? []).map((c) => ({ number: c.cfdaNumber ?? null, title: c.programTitle ?? null })),
    posting_date: s.postingDate ?? null,
    response_date: s.responseDate ?? null,
    closing_date_desc: s.closingDateDesc ?? null,
    archive_date: s.archiveDate ?? null,
    contact_name: s.agencyContactName ?? null,
    contact_email: s.agencyContactEmail ?? null,
    contact_phone: s.agencyContactPhone ?? null,
    attachments: (d.synopsisAttachmentFolders ?? []).flatMap((f) =>
      (f.attachments ?? []).map((a) => ({
        folder: f.folderName ?? null,
        file_name: a.fileName ?? null,
        download_url: a.downloadURL ?? null,
      })),
    ),
    grants_gov_url: d.id ? `https://www.grants.gov/search-results-detail/${d.id}` : null,
  };
}
