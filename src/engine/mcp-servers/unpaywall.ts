/**
 * Unpaywall REST API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.unpaywall.org/v2
// Auth: None — free and open. A contact email is required as a polite-pool
//       identifier (query param ?email=...). No API key.
// Docs: https://unpaywall.org/products/api
// Category: research
// Rate limits: No hard cap documented; contact email required for polite pool.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.unpaywall.org/v2';

// Default contact email for polite-pool identification.
// Override via config.email or UNPAYWALL_EMAIL env var.
const DEFAULT_EMAIL = process.env['UNPAYWALL_EMAIL'] ?? 'hello@epicai.com';

// ── Response type helpers ──────────────────────────────────────────────────────

interface OaLocation {
  url?: string;
  url_for_pdf?: string;
  host_type?: string;
  version?: string;
  license?: string;
  is_best?: boolean;
  evidence?: string;
  repository_institution?: string;
}

interface OaRecord {
  doi?: string;
  doi_url?: string;
  title?: string;
  genre?: string;
  is_oa?: boolean;
  oa_status?: string;
  has_repository_copy?: boolean;
  journal_name?: string;
  journal_issns?: string;
  journal_is_oa?: boolean;
  journal_is_in_doaj?: boolean;
  publisher?: string;
  published_date?: string;
  year?: number;
  best_oa_location?: OaLocation | null;
  oa_locations?: OaLocation[];
  z_authors?: { given?: string; family?: string }[];
}

interface SearchResponse {
  results?: { response?: OaRecord; score?: number }[];
}

// ── Config ─────────────────────────────────────────────────────────────────────

interface UnpaywallConfig {
  email?: string;
  baseUrl?: string;
}

// ── Adapter ────────────────────────────────────────────────────────────────────

export class UnpaywallMCPServer extends MCPAdapterBase {
  private readonly email: string;
  private readonly baseUrl: string;

  constructor(config?: UnpaywallConfig) {
    super();
    if (config === null) { throw new Error('UnpaywallMCPServer: configuration object is required when provided'); }
    this.email = config?.email?.trim() || DEFAULT_EMAIL;
    this.baseUrl = config?.baseUrl || BASE_URL;
  }

  static catalog() {
    return {
      name: 'unpaywall',
      displayName: 'Unpaywall Open Access',
      version: '1.0.0',
      category: 'research',
      keywords: [
        'unpaywall', 'open access', 'oa', 'doi', 'scholarly', 'academic',
        'papers', 'research', 'publications', 'free pdf', 'preprint',
        'repository', 'gold', 'green', 'hybrid', 'bronze', 'science',
        'journal', 'bibliography',
      ],
      toolNames: ['get_oa', 'search_papers'],
      description: 'Unpaywall API: look up open-access status and free legal copies for scholarly papers by DOI, and search across Unpaywall\'s coverage by keyword.',
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
        name: 'get_oa',
        description:
          'Given a DOI, fetch open-access status and the best free legal copy if one exists. ' +
          'Returns is_oa, oa_status (gold | green | hybrid | bronze | closed), best location ' +
          '(URL, host type, license), and journal metadata.',
        inputSchema: {
          type: 'object',
          properties: {
            doi: {
              type: 'string',
              description: 'DOI of the paper (e.g. "10.1038/nature12373")',
            },
          },
          required: ['doi'],
        },
      },
      {
        name: 'search_papers',
        description:
          'Keyword search across Unpaywall\'s coverage of scholarly papers. ' +
          'Optionally restrict to OA-only results. Returns up to 50 results per page.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search term',
            },
            is_oa: {
              type: 'boolean',
              description: 'Restrict results to open-access papers only',
            },
            page: {
              type: 'number',
              description: '1-based page number (default 1)',
            },
          },
          required: ['query'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_oa':      return this.getOa(args);
        case 'search_papers': return this.searchPapers(args);
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

  private async request<T>(path: string): Promise<T | null> {
    const separator = path.includes('?') ? '&' : '?';
    const url = `${this.baseUrl}${path}${separator}email=${encodeURIComponent(this.email)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) throw new Error('Unpaywall: DOI not found');
    if (response.status === 422) throw new Error('Unpaywall: invalid DOI or query (HTTP 422)');
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      throw new Error(`Unpaywall error: ${response.status} ${errText.slice(0, 200)}`);
    }
    return response.json() as Promise<T>;
  }

  private normalizeLocation(loc: OaLocation | null | undefined): Record<string, unknown> | null {
    if (!loc) return null;
    return {
      url: loc.url ?? null,
      pdf_url: loc.url_for_pdf ?? null,
      host_type: loc.host_type ?? null,
      version: loc.version ?? null,
      license: loc.license ?? null,
      repository: loc.repository_institution ?? null,
      evidence: loc.evidence ?? null,
    };
  }

  private normalizeRecord(r: OaRecord): Record<string, unknown> {
    return {
      doi: r.doi ?? null,
      doi_url: r.doi_url ?? null,
      title: r.title ?? null,
      genre: r.genre ?? null,
      year: r.year ?? null,
      published_date: r.published_date ?? null,
      publisher: r.publisher ?? null,
      journal_name: r.journal_name ?? null,
      journal_issns: r.journal_issns ?? null,
      journal_is_oa: r.journal_is_oa ?? null,
      journal_in_doaj: r.journal_is_in_doaj ?? null,
      is_oa: r.is_oa ?? false,
      oa_status: r.oa_status ?? null,
      has_repository_copy: r.has_repository_copy ?? null,
      authors: (r.z_authors ?? [])
        .map((a) => [a.given, a.family].filter(Boolean).join(' '))
        .filter(Boolean),
      best_location: this.normalizeLocation(r.best_oa_location),
      other_locations: (r.oa_locations ?? [])
        .filter((l) => !l.is_best)
        .map((l) => this.normalizeLocation(l))
        .filter(Boolean),
    };
  }

  private async getOa(args: Record<string, unknown>): Promise<ToolResult> {
    const doi = args['doi'];
    if (!doi || typeof doi !== 'string' || !doi.trim()) {
      return { content: [{ type: 'text', text: 'get_oa: doi is required' }], isError: true };
    }
    const data = await this.request<OaRecord>(`/${encodeURIComponent(doi.trim())}`);
    if (!data) {
      return { content: [{ type: 'text', text: 'get_oa: no data returned' }], isError: true };
    }
    return { content: [{ type: 'text', text: this.truncate(this.normalizeRecord(data)) }], isError: false };
  }

  private async searchPapers(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args['query'];
    if (!query || typeof query !== 'string' || !query.trim()) {
      return { content: [{ type: 'text', text: 'search_papers: query is required' }], isError: true };
    }
    const params = new URLSearchParams({ query: query.trim() });
    if (args['is_oa'] === true) params.set('is_oa', 'true');
    if (typeof args['page'] === 'number' && args['page'] > 0) {
      params.set('page', String(Math.floor(args['page'])));
    }
    const data = await this.request<SearchResponse>(`/search?${params.toString()}`);
    if (!data) {
      return { content: [{ type: 'text', text: 'search_papers: no data returned' }], isError: true };
    }
    const results = (data.results ?? [])
      .filter((r) => r.response)
      .map((r) => ({ score: r.score ?? null, ...this.normalizeRecord(r.response as OaRecord) }));
    const out = {
      query: query.trim(),
      page: typeof args['page'] === 'number' ? args['page'] : 1,
      returned: results.length,
      results,
    };
    return { content: [{ type: 'text', text: this.truncate(out) }], isError: false };
  }
}
