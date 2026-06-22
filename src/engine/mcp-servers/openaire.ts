/**
 * OpenAIRE Graph API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL : https://api.openaire.eu/graph/v1
 * Auth     : None — public API, no key required.
 * Docs     : https://graph.openaire.eu/docs/apis/graph-api/
 * Category : research
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.openaire.eu/graph/v1';

export class OpenaireMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'openaire',
      displayName: 'OpenAIRE Graph API',
      version: '1.0.0',
      category: 'research' as const,
      keywords: [
        'openaire', 'research', 'publications', 'scholarly', 'academic',
        'datasets', 'software', 'projects', 'eu', 'cordis', 'funding',
        'open access', 'preprints', 'theses', 'arxiv', 'doi', 'science',
        'nsf', 'nih', 'horizon', 'grant', 'bibliographic',
      ],
      toolNames: [
        'search_publications',
        'search_datasets',
        'search_software',
        'search_projects',
        'get_research_product',
        'get_project',
      ],
      description: 'OpenAIRE Graph API: search and retrieve EU and global scholarly publications, research datasets, software, and funded projects (CORDIS, NSF, NIH, and more) — free, no authentication required.',
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
        name: 'search_publications',
        description: 'Search scholarly publications (articles, preprints, theses, books) in the OpenAIRE Graph.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Free-text query (matches title, abstract, keywords)' },
            size: { type: 'number', description: 'Page size, 1–100 (default 20)' },
            page: { type: 'number', description: '1-based page number (default 1)' },
            funder: { type: 'string', description: 'Funder short name — e.g. "EC", "NIH", "NSF", "WT"' },
            country: { type: 'string', description: 'Country code — ISO 3166-1 alpha-2' },
            from_year: { type: 'string', description: 'Earliest publication year (YYYY)' },
            to_year: { type: 'string', description: 'Latest publication year (YYYY)' },
            open_access: { type: 'boolean', description: 'Restrict to open-access publications when true' },
          },
          required: ['query'],
        },
      },
      {
        name: 'search_datasets',
        description: 'Search research datasets registered in the OpenAIRE Graph.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Free-text query (matches title, abstract, keywords)' },
            size: { type: 'number', description: 'Page size, 1–100 (default 20)' },
            page: { type: 'number', description: '1-based page number (default 1)' },
            from_year: { type: 'string', description: 'Earliest publication year (YYYY)' },
            to_year: { type: 'string', description: 'Latest publication year (YYYY)' },
          },
          required: ['query'],
        },
      },
      {
        name: 'search_software',
        description: 'Search research software registrations in the OpenAIRE Graph.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Free-text query (matches title, abstract, keywords)' },
            size: { type: 'number', description: 'Page size, 1–100 (default 20)' },
            page: { type: 'number', description: '1-based page number (default 1)' },
          },
          required: ['query'],
        },
      },
      {
        name: 'search_projects',
        description: 'Search funded research projects (CORDIS for EC; also NSF, NIH, Wellcome Trust, etc.).',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Free-text query (matches title, abstract, keywords)' },
            size: { type: 'number', description: 'Page size, 1–100 (default 20)' },
            page: { type: 'number', description: '1-based page number (default 1)' },
            funder: { type: 'string', description: 'Funder short name — e.g. "EC", "NIH", "NSF"' },
            country: { type: 'string', description: 'Coordinator country — ISO 3166-1 alpha-2' },
            from_year: { type: 'string', description: 'Earliest project start year (YYYY)' },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_research_product',
        description: 'Fetch a single research product (publication, dataset, or software) by its OpenAIRE id.',
        inputSchema: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'OpenAIRE identifier (e.g. "doi_dedup___::abc...")' },
          },
          required: ['id'],
        },
      },
      {
        name: 'get_project',
        description: 'Fetch a single funded project by its OpenAIRE id.',
        inputSchema: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'OpenAIRE project identifier (e.g. "corda__h2020::...")' },
          },
          required: ['id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_publications':  return this.searchProducts('publication', args);
        case 'search_datasets':      return this.searchProducts('dataset', args);
        case 'search_software':      return this.searchProducts('software', args);
        case 'search_projects':      return this.searchProjects(args);
        case 'get_research_product': return this.fetchById('researchProducts', this.requireString(args, 'id'));
        case 'get_project':          return this.fetchById('projects', this.requireString(args, 'id'));
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

  private async searchProducts(type: string, args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      search: String(args.query),
      type,
      pageSize: String(Math.min(100, Math.max(1, ((args.size as number) ?? 20)))),
      page: String(Math.max(1, ((args.page as number) ?? 1))),
    });
    if (args.funder) params.set('relFundingShortName', String(args.funder));
    if (args.country) params.set('country', String(args.country));
    if (args.from_year) params.set('fromPublicationDate', `${args.from_year}-01-01`);
    if (args.to_year) params.set('toPublicationDate', `${args.to_year}-12-31`);
    if (args.open_access === true) params.set('bestOpenAccessRouteImpl', 'gold');
    return this.openaireFetch('researchProducts', params);
  }

  private async searchProjects(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      search: String(args.query),
      pageSize: String(Math.min(100, Math.max(1, ((args.size as number) ?? 20)))),
      page: String(Math.max(1, ((args.page as number) ?? 1))),
    });
    if (args.funder) params.set('fundingShortName', String(args.funder));
    if (args.country) params.set('relOrganizationCountryCode', String(args.country));
    if (args.from_year) params.set('fromStartDate', `${args.from_year}-01-01`);
    return this.openaireFetch('projects', params);
  }

  private async openaireFetch(kind: string, params: URLSearchParams): Promise<ToolResult> {
    const url = `${BASE_URL}/${kind}?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `OpenAIRE API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json() as {
      header?: { numFound?: number; pageSize?: number; page?: number };
      results?: unknown[];
    };
    const result = {
      total: data.header?.numFound ?? null,
      page: data.header?.page ?? null,
      page_size: data.header?.pageSize ?? null,
      count: data.results?.length ?? 0,
      results: data.results ?? [],
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async fetchById(kind: string, id: string): Promise<ToolResult> {
    const params = new URLSearchParams({ id });
    const url = `${BASE_URL}/${kind}?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `OpenAIRE API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json() as { results?: unknown[] };
    const first = data.results?.[0];
    if (!first) {
      return {
        content: [{ type: 'text', text: `OpenAIRE: ${kind} with id "${id}" not found` }],
        isError: true,
      };
    }
    return { content: [{ type: 'text', text: this.truncate(first) }], isError: false };
  }

  private requireString(args: Record<string, unknown>, key: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty.`);
    }
    return v;
  }
}
