/**
 * Crossref REST API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.crossref.org
// Auth: None — Crossref REST API is public and free
// Docs: https://api.crossref.org/swagger-ui/index.html
// Category: research
// Rate limits: Polite pool with mailto User-Agent header; no hard cap documented

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.crossref.org';
const USER_AGENT = 'epic-ai-chariot/1.0 (mailto:hello@epicai.com)';

// ── Response type helpers ──────────────────────────────────────────────────────

type CrossrefAuthor = {
  given?: string;
  family?: string;
  name?: string;
  ORCID?: string;
};

type CrossrefDate = {
  'date-parts': number[][];
  'date-time'?: string;
  timestamp?: number;
};

type CrossrefWork = {
  DOI: string;
  title?: string[];
  'container-title'?: string[];
  author?: CrossrefAuthor[];
  published?: CrossrefDate;
  'published-print'?: CrossrefDate;
  'published-online'?: CrossrefDate;
  abstract?: string;
  type?: string;
  publisher?: string;
  URL?: string;
  'is-referenced-by-count'?: number;
  score?: number;
  subject?: string[];
  ISSN?: string[];
  volume?: string;
  issue?: string;
  page?: string;
};

type CrossrefMessage<T> = {
  status: string;
  'message-type': string;
  message: T;
};

type CrossrefWorksMessage = {
  'total-results': number;
  items: CrossrefWork[];
  query?: { 'search-terms': string; 'start-index': number };
};

type CrossrefJournalWorksMessage = {
  'total-results': number;
  items: CrossrefWork[];
};

function formatAuthor(a: CrossrefAuthor): string {
  if (a.family && a.given) return `${a.given} ${a.family}`;
  if (a.family) return a.family;
  return a.name ?? 'Unknown';
}

function formatDate(d?: CrossrefDate): string | null {
  if (!d) return null;
  const parts = d['date-parts']?.[0];
  if (!parts) return null;
  return parts.filter(Boolean).join('-');
}

function mapWork(w: CrossrefWork) {
  return {
    doi: w.DOI,
    title: w.title?.[0] ?? null,
    journal: w['container-title']?.[0] ?? null,
    authors: (w.author ?? []).map(formatAuthor),
    published: formatDate(w.published ?? w['published-print'] ?? w['published-online']),
    type: w.type ?? null,
    publisher: w.publisher ?? null,
    abstract: w.abstract ?? null,
    citations: w['is-referenced-by-count'] ?? null,
    subjects: w.subject ?? [],
    url: w.URL ?? `https://doi.org/${w.DOI}`,
  };
}

// ── Adapter ────────────────────────────────────────────────────────────────────

export class CrossrefMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('CrossrefMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'crossref',
      displayName: 'Crossref',
      version: '1.0.0',
      category: 'research',
      keywords: [
        'crossref', 'academic', 'papers', 'doi', 'scholarly', 'publications',
        'journals', 'citations', 'metadata', 'research', 'science', 'bibliography',
        'issn', 'works', 'authors',
      ],
      toolNames: ['search_works', 'get_work', 'get_journal'],
      description: 'Crossref REST API: search academic works by keyword, retrieve full metadata for a DOI, and list recent works in a journal by ISSN. Free and unauthenticated.',
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
        description:
          'Search academic works (papers, books, datasets) in the Crossref index by keyword. Returns title, authors, journal, DOI, and citation count.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query (e.g., "climate change machine learning")',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (1–100, default 10)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_work',
        description:
          'Get full metadata for a specific academic work by its DOI. Returns title, authors, abstract, journal, publisher, citation count, and subjects.',
        inputSchema: {
          type: 'object',
          properties: {
            doi: {
              type: 'string',
              description: 'DOI of the work (e.g., "10.1038/nature12373")',
            },
          },
          required: ['doi'],
        },
      },
      {
        name: 'get_journal',
        description:
          'Get the 5 most recent works published in a journal by its ISSN. Returns title, authors, DOI, and publication date.',
        inputSchema: {
          type: 'object',
          properties: {
            issn: {
              type: 'string',
              description: 'Journal ISSN (e.g., "1476-4687" for Nature)',
            },
          },
          required: ['issn'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_works': return this.searchWorks(args);
        case 'get_work':     return this.getWork(args);
        case 'get_journal':  return this.getJournal(args);
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

  private async searchWorks(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const rows = Math.min(100, Math.max(1, typeof args.limit === 'number' ? args.limit : 10));
    const params = new URLSearchParams({ query, rows: String(rows) });
    const url = `${this.baseUrl}/works?${params.toString()}`;

    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': USER_AGENT },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Crossref search error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as CrossrefMessage<CrossrefWorksMessage>;
    const result = {
      total_results: data.message['total-results'],
      results: data.message.items.map(mapWork),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getWork(args: Record<string, unknown>): Promise<ToolResult> {
    const doi = encodeURIComponent(args.doi as string);
    const url = `${this.baseUrl}/works/${doi}`;

    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': USER_AGENT },
    });

    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: `Work not found for DOI: ${args.doi as string}` }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Crossref work error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as CrossrefMessage<CrossrefWork>;
    return { content: [{ type: 'text', text: this.truncate(mapWork(data.message)) }], isError: false };
  }

  private async getJournal(args: Record<string, unknown>): Promise<ToolResult> {
    const issn = args.issn as string;
    const params = new URLSearchParams({ rows: '5' });
    const url = `${this.baseUrl}/journals/${encodeURIComponent(issn)}/works?${params.toString()}`;

    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json', 'User-Agent': USER_AGENT },
    });

    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: `Journal not found for ISSN: ${issn}` }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Crossref journal error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as CrossrefMessage<CrossrefJournalWorksMessage>;
    const result = {
      issn,
      total_results: data.message['total-results'],
      recent_works: data.message.items.map(mapWork),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
