/**
 * CFPB (Consumer Financial Protection Bureau) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: https://www.consumerfinance.gov/data-research/consumer-complaints/search/api/v1/
 * Auth: none (public government API)
 * Docs: https://cfpb.github.io/api/ccdb/api.html
 * Category: finance
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://www.consumerfinance.gov/data-research/consumer-complaints/search/api/v1/';

// ── Internal types ──────────────────────────────────────────────────────────

interface CfpbHit {
  _source: {
    complaint_id: string;
    date_received: string;
    product: string;
    sub_product?: string;
    issue: string;
    sub_issue?: string;
    complaint_what_happened?: string;
    company: string;
    state?: string;
    zip_code?: string;
    company_public_response?: string;
    company_response: string;
    timely?: string;
    consumer_disputed?: string;
    consumer_consent_provided?: string;
    submitted_via?: string;
    date_sent_to_company?: string;
    tags?: string;
  };
}

interface CfpbResponse {
  hits: {
    hits: CfpbHit[];
    total: number;
  };
  aggregations?: {
    company?: { company?: { buckets: { key: string; doc_count: number }[] } };
    product?: { product?: { buckets: { key: string; doc_count: number }[] } };
  };
  _meta?: { total_record_count: number };
}

// ── Adapter class ───────────────────────────────────────────────────────────

export class CfpbMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('CfpbMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'cfpb',
      displayName: 'CFPB Consumer Complaints',
      version: '1.0.0',
      category: 'finance',
      keywords: [
        'cfpb', 'consumer financial protection bureau', 'complaints', 'consumer complaints',
        'bank', 'mortgage', 'credit card', 'student loan', 'debt collection',
        'credit reporting', 'financial', 'regulatory', 'government', 'fintech',
        'compliance', 'company response', 'consumer protection',
      ],
      toolNames: [
        'cfpb_search_complaints',
        'cfpb_company_complaints',
        'cfpb_get_complaint',
        'cfpb_top_companies',
        'cfpb_product_breakdown',
      ],
      description: 'CFPB Consumer Complaints: search and analyze the Consumer Financial Protection Bureau complaint database — filter by keyword, company, product, and date; retrieve individual complaints and aggregate statistics.',
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
        name: 'cfpb_search_complaints',
        description:
          'Search the CFPB consumer complaint database. Filter by keyword, company, product category, and date range. Returns complaint narratives, company responses, and resolution status.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search term (e.g., "overdraft fees", "denied claim"). Optional if other filters provided.',
            },
            company: {
              type: 'string',
              description: 'Company name to filter by (e.g., "BANK OF AMERICA", "WELLS FARGO")',
            },
            product: {
              type: 'string',
              description:
                'Product category (e.g., "Credit card", "Mortgage", "Student loan", "Vehicle loan or lease", "Checking or savings account", "Credit reporting", "Debt collection")',
            },
            start_date: {
              type: 'string',
              description: 'Start date in YYYY-MM-DD format',
            },
            end_date: {
              type: 'string',
              description: 'End date in YYYY-MM-DD format',
            },
            limit: {
              type: 'number',
              description: 'Number of results (1-100, default 25)',
            },
          },
        },
      },
      {
        name: 'cfpb_company_complaints',
        description:
          'Get recent consumer complaints for a specific company, sorted by newest first. Returns complaint details and company response information.',
        inputSchema: {
          type: 'object',
          properties: {
            company: {
              type: 'string',
              description: 'Company name (e.g., "BANK OF AMERICA", "CITIBANK", "JPMORGAN CHASE")',
            },
            limit: {
              type: 'number',
              description: 'Number of results (1-100, default 25)',
            },
          },
          required: ['company'],
        },
      },
      {
        name: 'cfpb_get_complaint',
        description: 'Get full details for a single consumer complaint by its complaint ID number.',
        inputSchema: {
          type: 'object',
          properties: {
            complaint_id: {
              type: 'string',
              description: 'CFPB complaint ID number',
            },
          },
          required: ['complaint_id'],
        },
      },
      {
        name: 'cfpb_top_companies',
        description:
          'Get the companies with the most consumer complaints in a given date range. Useful for identifying which companies receive the most complaints.',
        inputSchema: {
          type: 'object',
          properties: {
            start_date: {
              type: 'string',
              description: 'Start date in YYYY-MM-DD format',
            },
            end_date: {
              type: 'string',
              description: 'End date in YYYY-MM-DD format',
            },
            product: {
              type: 'string',
              description: 'Optional product filter (e.g., "Mortgage", "Credit card")',
            },
            limit: {
              type: 'number',
              description: 'Number of top companies to return (default 10)',
            },
          },
        },
      },
      {
        name: 'cfpb_product_breakdown',
        description:
          'Get complaint counts broken down by product category. Optionally filter by company and/or date range.',
        inputSchema: {
          type: 'object',
          properties: {
            company: {
              type: 'string',
              description: 'Optional company name to filter by',
            },
            start_date: {
              type: 'string',
              description: 'Start date in YYYY-MM-DD format',
            },
            end_date: {
              type: 'string',
              description: 'End date in YYYY-MM-DD format',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'cfpb_search_complaints':
          return this.searchComplaints(args);
        case 'cfpb_company_complaints':
          return this.companyComplaints(args);
        case 'cfpb_get_complaint':
          return this.getComplaint(args);
        case 'cfpb_top_companies':
          return this.topCompanies(args);
        case 'cfpb_product_breakdown':
          return this.productBreakdown(args);
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

  private formatComplaint(hit: CfpbHit): Record<string, unknown> {
    const s = hit._source;
    return {
      complaint_id: s.complaint_id,
      date_received: s.date_received,
      product: s.product,
      sub_product: s.sub_product ?? null,
      issue: s.issue,
      sub_issue: s.sub_issue ?? null,
      narrative: s.complaint_what_happened ?? null,
      company: s.company,
      state: s.state ?? null,
      company_response: s.company_response,
      company_public_response: s.company_public_response ?? null,
      timely: s.timely ?? null,
      consumer_disputed: s.consumer_disputed ?? null,
      submitted_via: s.submitted_via ?? null,
    };
  }

  private async searchComplaints(args: Record<string, unknown>): Promise<ToolResult> {
    const query      = args.query      as string | undefined;
    const company    = args.company    as string | undefined;
    const product    = args.product    as string | undefined;
    const start_date = args.start_date as string | undefined;
    const end_date   = args.end_date   as string | undefined;
    const limit      = args.limit      as number | undefined;

    const size = Math.min(100, Math.max(1, limit ?? 25));
    const params = new URLSearchParams({ size: String(size), sort: 'created_date_desc', field: 'all' });

    if (query)      params.set('search_term',        query);
    if (company)    params.set('company',             company);
    if (product)    params.set('product',             product);
    if (start_date) params.set('date_received_min',   start_date);
    if (end_date)   params.set('date_received_max',   end_date);

    const response = await this.fetchWithRetry(`${this.baseUrl}?${params}`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `CFPB API error: ${response.status} ${errText}` }], isError: true };
    }

    const data = (await response.json()) as CfpbResponse;
    const result = {
      query: query ?? null,
      filters: {
        company:    company    ?? null,
        product:    product    ?? null,
        date_range: { start: start_date ?? null, end: end_date ?? null },
      },
      total: data.hits?.total ?? 0,
      complaints: (data.hits?.hits ?? []).map((h) => this.formatComplaint(h)),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async companyComplaints(args: Record<string, unknown>): Promise<ToolResult> {
    const company = args.company as string;
    const limit   = args.limit   as number | undefined;

    const size = Math.min(100, Math.max(1, limit ?? 25));
    const params = new URLSearchParams({ company, size: String(size), sort: 'created_date_desc' });

    const response = await this.fetchWithRetry(`${this.baseUrl}?${params}`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `CFPB API error: ${response.status} ${errText}` }], isError: true };
    }

    const data = (await response.json()) as CfpbResponse;
    const result = {
      company,
      total: data.hits?.total ?? 0,
      complaints: (data.hits?.hits ?? []).map((h) => this.formatComplaint(h)),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getComplaint(args: Record<string, unknown>): Promise<ToolResult> {
    const complaint_id = args.complaint_id as string;

    const response = await this.fetchWithRetry(
      `${this.baseUrl}${encodeURIComponent(complaint_id)}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `CFPB API error: ${response.status} ${errText} — complaint ID "${complaint_id}" may not exist` }],
        isError: true,
      };
    }

    const data = (await response.json()) as { hits: { hits: CfpbHit[]; total: number } };

    if (!data.hits?.hits?.length) {
      return { content: [{ type: 'text', text: `Complaint not found: ${complaint_id}` }], isError: true };
    }

    return { content: [{ type: 'text', text: this.truncate(this.formatComplaint(data.hits.hits[0])) }], isError: false };
  }

  private async topCompanies(args: Record<string, unknown>): Promise<ToolResult> {
    const start_date = args.start_date as string | undefined;
    const end_date   = args.end_date   as string | undefined;
    const product    = args.product    as string | undefined;
    const limit      = args.limit      as number | undefined;

    const count = Math.min(50, Math.max(1, limit ?? 10));
    const params = new URLSearchParams({ size: '0', field: 'all' });

    if (start_date) params.set('date_received_min', start_date);
    if (end_date)   params.set('date_received_max', end_date);
    if (product)    params.set('product',            product);

    const response = await this.fetchWithRetry(`${this.baseUrl}?${params}`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `CFPB API error: ${response.status} ${errText}` }], isError: true };
    }

    const data = (await response.json()) as CfpbResponse;
    const buckets = data.aggregations?.company?.company?.buckets ?? [];

    const result = {
      filters: {
        product:    product    ?? null,
        date_range: { start: start_date ?? null, end: end_date ?? null },
      },
      total_complaints: data.hits?.total ?? 0,
      top_companies: buckets.slice(0, count).map((b, i) => ({
        rank:            i + 1,
        company:         b.key,
        complaint_count: b.doc_count,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async productBreakdown(args: Record<string, unknown>): Promise<ToolResult> {
    const company    = args.company    as string | undefined;
    const start_date = args.start_date as string | undefined;
    const end_date   = args.end_date   as string | undefined;

    const params = new URLSearchParams({ size: '0', field: 'all' });

    if (company)    params.set('company',           company);
    if (start_date) params.set('date_received_min', start_date);
    if (end_date)   params.set('date_received_max', end_date);

    const response = await this.fetchWithRetry(`${this.baseUrl}?${params}`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `CFPB API error: ${response.status} ${errText}` }], isError: true };
    }

    const data = (await response.json()) as CfpbResponse;
    const buckets = data.aggregations?.product?.product?.buckets ?? [];

    const result = {
      filters: {
        company:    company    ?? null,
        date_range: { start: start_date ?? null, end: end_date ?? null },
      },
      total_complaints: data.hits?.total ?? 0,
      products: buckets.map((b) => ({
        product:         b.key,
        complaint_count: b.doc_count,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
