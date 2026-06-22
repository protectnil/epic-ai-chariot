/**
 * DataCite MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// DataCite REST API — DOI registry for research datasets, software, samples,
// instruments and other non-traditional scholarly outputs (~50M DOIs).
//
// Base URL: https://api.datacite.org
// Auth: none (public, free)
// Docs: https://support.datacite.org/docs/api
// Category: research
// Rate limits: generous public tier; no hard published limit

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.datacite.org';

// ── Internal shape helpers ──────────────────────────────────────────────────

interface DoiAttributes {
  doi?: string;
  creators?: {
    name?: string;
    affiliation?: { name?: string }[];
    nameIdentifiers?: { nameIdentifier?: string; nameIdentifierScheme?: string }[];
  }[];
  titles?: { title?: string; lang?: string }[];
  publisher?: string;
  publicationYear?: number;
  types?: { resourceType?: string; resourceTypeGeneral?: string };
  subjects?: { subject?: string }[];
  dates?: { date?: string; dateType?: string }[];
  descriptions?: { description?: string; descriptionType?: string }[];
  sizes?: string[];
  formats?: string[];
  rightsList?: { rights?: string; rightsUri?: string }[];
  relatedIdentifiers?: {
    relatedIdentifier?: string;
    relatedIdentifierType?: string;
    relationType?: string;
  }[];
  url?: string;
  citationCount?: number;
  downloadCount?: number;
  viewCount?: number;
  registered?: string;
  updated?: string;
}

interface DoiResource {
  id?: string;
  attributes?: DoiAttributes;
}

interface RepoResource {
  id?: string;
  attributes?: {
    name?: string;
    symbol?: string;
    description?: string;
    url?: string;
    re3data?: string;
    repositoryType?: string[];
    domain?: string;
    yearCreated?: number;
  };
}

// ── Adapter ─────────────────────────────────────────────────────────────────

export class DataCiteMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('DataCiteMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'datacite',
      displayName: 'DataCite',
      version: '1.0.0',
      category: 'research',
      keywords: [
        'datacite', 'doi', 'dataset', 'software', 'research data',
        'scholarly', 'zenodo', 'dryad', 'figshare', 'citation',
        'repository', 'open data', 'science', 'metadata', 'orcid',
      ],
      toolNames: ['search_dois', 'get_doi', 'list_repositories'],
      description: 'DataCite: search and retrieve DOI metadata for ~50M research datasets, software, samples, and instruments registered in the DataCite DOI registry.',
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
        name: 'search_dois',
        description:
          'Search DataCite-registered DOIs. Filter by free-text query, resource type (Dataset, Software, etc.), year, publisher, or affiliation. Returns DOI, title, creators, publisher, type, year, citation count.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Free-text query (titles, descriptions, creators)',
            },
            resource_type: {
              type: 'string',
              description:
                'Dataset | Software | Text | Image | Sound | Other (case-sensitive)',
            },
            year: { type: 'number', description: 'Publication year' },
            publisher: { type: 'string', description: 'Publisher name filter' },
            affiliation: { type: 'string', description: 'Creator affiliation' },
            page_size: { type: 'number', description: '1-1000 (default 25)' },
            page: { type: 'number', description: '1-based page (default 1)' },
          },
        },
      },
      {
        name: 'get_doi',
        description:
          'Fetch a single DOI record. Returns full metadata: title(s), creators with affiliations and ORCIDs, abstract, publisher, year, dates, related identifiers, subjects, license, sizes/formats.',
        inputSchema: {
          type: 'object',
          properties: {
            doi: {
              type: 'string',
              description: 'DOI (e.g., "10.5281/zenodo.1234567")',
            },
          },
          required: ['doi'],
        },
      },
      {
        name: 'list_repositories',
        description:
          'List DataCite-registered data repositories (e.g., Zenodo, Dryad, Figshare). Filter by query. Useful for "where do I deposit a dataset" lookups.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Repository name / description filter' },
            page_size: { type: 'number', description: '1-1000 (default 25)' },
            page: { type: 'number', description: '1-based page' },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_dois':
          return this.searchDois(args);
        case 'get_doi':
          return this.getDoi(args);
        case 'list_repositories':
          return this.listRepositories(args);
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

  // ── Private helpers ────────────────────────────────────────────────────────

  private async dcFetch(path: string, params?: URLSearchParams): Promise<unknown> {
    const url = `${this.baseUrl}${path}${params ? `?${params.toString()}` : ''}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/vnd.api+json' },
    });
    if (response.status === 404) {
      throw new Error('DataCite: not found (HTTP 404)');
    }
    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      throw new Error(`DataCite error: ${response.status} ${body.slice(0, 200)}`);
    }
    return response.json();
  }

  private normalizeDoiSummary(r: DoiResource) {
    const a = r.attributes ?? {};
    return {
      doi: a.doi ?? r.id ?? null,
      title: (a.titles ?? [])[0]?.title ?? null,
      creators: (a.creators ?? []).map((c) => c.name).filter(Boolean),
      publisher: a.publisher ?? null,
      year: a.publicationYear ?? null,
      resource_type: a.types?.resourceTypeGeneral ?? a.types?.resourceType ?? null,
      url: a.url ?? null,
      citation_count: a.citationCount ?? null,
      download_count: a.downloadCount ?? null,
      view_count: a.viewCount ?? null,
      datacite_url: a.doi ? `https://commons.datacite.org/doi.org/${a.doi}` : null,
    };
  }

  private normalizeDoiFull(r: DoiResource) {
    const a = r.attributes ?? {};
    return {
      ...this.normalizeDoiSummary(r),
      titles: (a.titles ?? []).map((t) => ({ title: t.title ?? null, lang: t.lang ?? null })),
      creators_full: (a.creators ?? []).map((c) => ({
        name: c.name ?? null,
        affiliations: (c.affiliation ?? []).map((af) => af.name).filter(Boolean),
        orcid:
          c.nameIdentifiers?.find((i) => i.nameIdentifierScheme === 'ORCID')
            ?.nameIdentifier ?? null,
      })),
      subjects: (a.subjects ?? []).map((s) => s.subject).filter(Boolean),
      descriptions: (a.descriptions ?? []).map((d) => ({
        text: d.description ?? null,
        type: d.descriptionType ?? null,
      })),
      dates: (a.dates ?? []).map((d) => ({ date: d.date ?? null, type: d.dateType ?? null })),
      sizes: a.sizes ?? [],
      formats: a.formats ?? [],
      rights: (a.rightsList ?? []).map((r) => ({ name: r.rights ?? null, uri: r.rightsUri ?? null })),
      related: (a.relatedIdentifiers ?? []).map((r) => ({
        id: r.relatedIdentifier ?? null,
        type: r.relatedIdentifierType ?? null,
        relation: r.relationType ?? null,
      })),
      registered: a.registered ?? null,
      updated: a.updated ?? null,
    };
  }

  private async searchDois(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      'page[size]': String(Math.min(1000, Math.max(1, (args.page_size as number) ?? 25))),
      'page[number]': String(Math.max(1, (args.page as number) ?? 1)),
    });
    if (args.query) params.set('query', String(args.query));
    if (args.resource_type) params.set('resource-type-id', String(args.resource_type).toLowerCase());
    if (args.year) params.set('publication-year', String(args.year));
    if (args.publisher) params.set('publisher', String(args.publisher));
    if (args.affiliation) params.set('affiliation', String(args.affiliation));

    const data = (await this.dcFetch('/dois', params)) as {
      data?: DoiResource[];
      meta?: { total?: number; totalPages?: number };
    };

    const result = {
      total: data.meta?.total ?? 0,
      total_pages: data.meta?.totalPages ?? 0,
      returned: data.data?.length ?? 0,
      results: (data.data ?? []).map((r) => this.normalizeDoiSummary(r)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getDoi(args: Record<string, unknown>): Promise<ToolResult> {
    const doi = args.doi;
    if (typeof doi !== 'string' || !doi.trim()) {
      return {
        content: [
          {
            type: 'text',
            text: 'Required argument "doi" is missing or empty. Pass a string like "10.5281/zenodo.1234567".',
          },
        ],
        isError: true,
      };
    }

    const data = (await this.dcFetch(`/dois/${encodeURIComponent(doi.trim())}`)) as {
      data?: DoiResource;
    };

    if (!data.data) {
      return {
        content: [{ type: 'text', text: `DataCite: no record found for DOI ${doi}` }],
        isError: true,
      };
    }
    const result = this.normalizeDoiFull(data.data);
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async listRepositories(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({
      'page[size]': String(Math.min(1000, Math.max(1, (args.page_size as number) ?? 25))),
      'page[number]': String(Math.max(1, (args.page as number) ?? 1)),
    });
    if (args.query) params.set('query', String(args.query));

    const data = (await this.dcFetch('/clients', params)) as {
      data?: RepoResource[];
      meta?: { total?: number };
    };

    const result = {
      total: data.meta?.total ?? 0,
      returned: data.data?.length ?? 0,
      repositories: (data.data ?? []).map((r) => ({
        id: r.id ?? null,
        name: r.attributes?.name ?? null,
        symbol: r.attributes?.symbol ?? null,
        description: r.attributes?.description ?? null,
        url: r.attributes?.url ?? null,
        re3data_url: r.attributes?.re3data ?? null,
        repository_types: r.attributes?.repositoryType ?? [],
        domain: r.attributes?.domain ?? null,
        year_created: r.attributes?.yearCreated ?? null,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
