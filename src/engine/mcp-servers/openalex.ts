/**
 * OpenAlex MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://api.openalex.org
 * Auth: none (public, free, no key required)
 * Docs: https://docs.openalex.org
 * Category: research
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.openalex.org';

export class OpenAlexMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('OpenAlexMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl || BASE_URL;
  }

  static catalog() {
    return {
      name: 'openalex',
      displayName: 'OpenAlex Scholarly Works',
      version: '1.0.0',
      category: 'research',
      keywords: [
        'openalex', 'scholarly', 'academic', 'research', 'papers', 'works',
        'authors', 'institutions', 'concepts', 'citations', 'open access',
        'bibliography', 'university', 'journal', 'doi', 'orcid', 'science',
      ],
      toolNames: ['search_works', 'search_authors', 'search_institutions', 'get_concept'],
      description: 'OpenAlex API: search scholarly works, authors, academic institutions, and concepts — free, open-access, no authentication required.',
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
        name: 'search_works',
        description: 'Search scholarly works (papers, books, datasets) in the OpenAlex index. Returns title, authors, journal, year, citation count, and abstract.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query (e.g., "transformer neural networks")',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (1-25, default 10)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'search_authors',
        description: 'Search researchers and authors by name in OpenAlex. Returns display name, ORCID, institution, works count, and citation count.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Author name to search for (e.g., "Yoshua Bengio")',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (1-25, default 10)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'search_institutions',
        description: 'Search academic institutions (universities, research labs) by name in OpenAlex. Returns name, country, type, works count, and top concepts.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Institution name to search for (e.g., "MIT")',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (1-25, default 10)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_concept',
        description: 'Look up an academic concept or field of study by name. Returns description, works count, related concepts, and ancestor concepts in the hierarchy.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Concept name to look up (e.g., "deep learning")',
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
        case 'search_works':
          return this.searchWorks(args.query as string, (args.limit as number) ?? 10);
        case 'search_authors':
          return this.searchAuthors(args.query as string, (args.limit as number) ?? 10);
        case 'search_institutions':
          return this.searchInstitutions(args.query as string, (args.limit as number) ?? 10);
        case 'get_concept':
          return this.getConcept(args.query as string);
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

  private reconstructAbstract(invertedIndex: Record<string, number[]> | null): string | null {
    if (!invertedIndex) return null;
    const entries: Array<[number, string]> = [];
    for (const [word, positions] of Object.entries(invertedIndex)) {
      for (const pos of positions) {
        entries.push([pos, word]);
      }
    }
    entries.sort((a, b) => a[0] - b[0]);
    return entries.map(([, word]) => word).join(' ');
  }

  private mapWork(w: Record<string, unknown>): Record<string, unknown> {
    const openAccess = w.open_access as { is_oa?: boolean; oa_url?: string | null } | null;
    const primaryLocation = w.primary_location as { source?: { display_name?: string | null } | null } | null;
    const authorships = (w.authorships as Array<{ author?: { display_name?: string } }>) ?? [];
    const concepts = (w.concepts as Array<{ display_name?: string }>) ?? [];
    return {
      id: w.id,
      doi: w.doi ?? null,
      title: (w.display_name ?? w.title) ?? null,
      publication_year: w.publication_year ?? null,
      type: w.type ?? null,
      open_access: openAccess?.is_oa ?? false,
      oa_url: openAccess?.oa_url ?? null,
      cited_by_count: w.cited_by_count,
      journal: primaryLocation?.source?.display_name ?? null,
      authors: authorships.map((a) => a.author?.display_name ?? ''),
      concepts: concepts.slice(0, 5).map((c) => c.display_name ?? ''),
      abstract: this.reconstructAbstract(
        (w.abstract_inverted_index as Record<string, number[]> | null) ?? null,
      ),
    };
  }

  private async request(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as unknown;
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchWorks(query: string, limit: number): Promise<ToolResult> {
    const perPage = Math.min(25, Math.max(1, limit));
    const params = new URLSearchParams({ search: query, per_page: String(perPage) });
    const url = `${this.baseUrl}/works?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `OpenAlex works search error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as { meta: { count: number }; results: Record<string, unknown>[] };
    const result = {
      total: data.meta.count,
      results: data.results.map((w) => this.mapWork(w)),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async searchAuthors(query: string, limit: number): Promise<ToolResult> {
    const perPage = Math.min(25, Math.max(1, limit));
    const params = new URLSearchParams({ search: query, per_page: String(perPage) });
    const url = `${this.baseUrl}/authors?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `OpenAlex authors search error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as {
      meta: { count: number };
      results: Array<{
        id: string;
        display_name: string;
        orcid: string | null;
        works_count: number;
        cited_by_count: number;
        last_known_institution: { display_name: string | null; country_code: string | null } | null;
        x_concepts: Array<{ display_name: string }>;
      }>;
    };
    const result = {
      total: data.meta.count,
      results: data.results.map((a) => ({
        id: a.id,
        display_name: a.display_name,
        orcid: a.orcid ?? null,
        works_count: a.works_count,
        cited_by_count: a.cited_by_count,
        last_known_institution: a.last_known_institution?.display_name ?? null,
        institution_country: a.last_known_institution?.country_code ?? null,
        top_concepts: a.x_concepts.slice(0, 5).map((c) => c.display_name),
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async searchInstitutions(query: string, limit: number): Promise<ToolResult> {
    const perPage = Math.min(25, Math.max(1, limit));
    const params = new URLSearchParams({ search: query, per_page: String(perPage) });
    const url = `${this.baseUrl}/institutions?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `OpenAlex institutions search error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as {
      meta: { count: number };
      results: Array<{
        id: string;
        display_name: string;
        ror: string | null;
        country_code: string | null;
        type: string | null;
        works_count: number;
        cited_by_count: number;
        homepage_url: string | null;
        x_concepts: Array<{ display_name: string }>;
      }>;
    };
    const result = {
      total: data.meta.count,
      results: data.results.map((i) => ({
        id: i.id,
        display_name: i.display_name,
        ror: i.ror ?? null,
        country_code: i.country_code ?? null,
        type: i.type ?? null,
        works_count: i.works_count,
        cited_by_count: i.cited_by_count,
        homepage_url: i.homepage_url ?? null,
        top_concepts: i.x_concepts.slice(0, 5).map((c) => c.display_name),
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getConcept(query: string): Promise<ToolResult> {
    const params = new URLSearchParams({ search: query, per_page: '1' });
    const url = `${this.baseUrl}/concepts?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `OpenAlex concepts search error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json() as {
      results: Array<{
        id: string;
        display_name: string;
        level: number;
        description: string | null;
        works_count: number;
        cited_by_count: number;
        ancestors: Array<{ id: string; display_name: string; level: number }>;
        related_concepts: Array<{ id: string; display_name: string; level: number; score: number }>;
      }>;
    };
    if (data.results.length === 0) {
      return {
        content: [{ type: 'text', text: `No concept found for: "${query}"` }],
        isError: true,
      };
    }
    const c = data.results[0];
    const result = {
      id: c.id,
      display_name: c.display_name,
      level: c.level,
      description: c.description ?? null,
      works_count: c.works_count,
      cited_by_count: c.cited_by_count,
      ancestors: c.ancestors.map((a) => ({ name: a.display_name, level: a.level })),
      related_concepts: c.related_concepts
        .slice(0, 10)
        .map((r) => ({ name: r.display_name, level: r.level, score: r.score })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
