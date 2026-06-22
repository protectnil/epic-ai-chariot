/**
 * Open Library MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official upstream: Internet Archive Open Library
// REST API — no authentication required (public domain)
//
// Base URL: https://openlibrary.org
// Covers: https://covers.openlibrary.org
// Auth: none
// Docs: https://openlibrary.org/developers/api
// Category: books

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://openlibrary.org';
const COVERS_URL = 'https://covers.openlibrary.org';

export class OpenLibraryMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'open-library',
      displayName: 'Open Library',
      version: '1.0.0',
      category: 'books',
      keywords: [
        'open library', 'books', 'isbn', 'authors', 'works', 'editions',
        'internet archive', 'book search', 'bibliography', 'book metadata',
        'out of print', 'covers', 'subjects', 'literature',
      ],
      toolNames: ['search_books', 'get_book_by_isbn', 'get_work', 'get_author'],
      description: 'Open Library (Internet Archive): search 50M+ book editions, look up by ISBN, fetch canonical work records, and retrieve author bios — free and unauthenticated.',
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
        name: 'search_books',
        description:
          'Search Open Library by title, author, or subject. Use prefixed terms: `title:gatsby author:fitzgerald` or plain text for broad search. Returns work key, title, author, first publish year, edition count, ISBNs, and cover ID.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search string (prefixed or plain)' },
            limit: { type: 'number', description: 'Results to return (1-100, default 20)' },
            page: { type: 'number', description: '1-based page (default 1)' },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_book_by_isbn',
        description:
          'Look up a single book by ISBN (10 or 13). Returns title, authors, publishers, publish date, page count, subjects, identifiers, and cover URL.',
        inputSchema: {
          type: 'object',
          properties: {
            isbn: { type: 'string', description: 'ISBN-10 or ISBN-13 (hyphens optional)' },
          },
          required: ['isbn'],
        },
      },
      {
        name: 'get_work',
        description:
          'Fetch the canonical "work" record (concept of a book across editions). Returns title, description, subjects, first publish date, links to editions and the author.',
        inputSchema: {
          type: 'object',
          properties: {
            work_id: {
              type: 'string',
              description: 'Open Library work ID (e.g., "OL45804W" — the W-suffixed identifier)',
            },
          },
          required: ['work_id'],
        },
      },
      {
        name: 'get_author',
        description:
          'Fetch an author record. Returns bio, birth/death dates, alternate names, and links to works.',
        inputSchema: {
          type: 'object',
          properties: {
            author_id: {
              type: 'string',
              description: 'Open Library author ID (e.g., "OL34184A" — the A-suffixed identifier)',
            },
          },
          required: ['author_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_books':   return this.searchBooks(args);
        case 'get_book_by_isbn': return this.getBookByIsbn(args);
        case 'get_work':       return this.getWork(args);
        case 'get_author':     return this.getAuthor(args);
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

  private coverUrl(coverId?: number | null, size: 'S' | 'M' | 'L' = 'M'): string | null {
    return coverId ? `${COVERS_URL}/b/id/${coverId}-${size}.jpg` : null;
  }

  private reqStr(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty. Pass a string like ${example}.`);
    }
    return v;
  }

  private async olRequest<T>(path: string): Promise<T> {
    const url = `${BASE_URL}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      throw new Error('Open Library: not found (HTTP 404)');
    }
    if (!response.ok) {
      const body = await response.text().catch(() => response.statusText);
      throw new Error(`Open Library error: ${response.status} ${body.slice(0, 200)}`);
    }
    return response.json() as Promise<T>;
  }

  private async searchBooks(args: Record<string, unknown>): Promise<ToolResult> {
    const query = this.reqStr(args, 'query', '"the great gatsby" or "author:fitzgerald"');
    const limit = Math.min(100, Math.max(1, typeof args.limit === 'number' ? args.limit : 20));
    const page = Math.max(1, typeof args.page === 'number' ? args.page : 1);

    const params = new URLSearchParams({
      q: query,
      limit: String(limit),
      page: String(page),
    });

    const data = await this.olRequest<{
      numFound?: number;
      start?: number;
      docs?: {
        key?: string;
        title?: string;
        author_name?: string[];
        author_key?: string[];
        first_publish_year?: number;
        edition_count?: number;
        isbn?: string[];
        cover_i?: number;
        language?: string[];
        subject?: string[];
        ratings_average?: number;
      }[];
    }>(`/search.json?${params}`);

    const result = {
      total: data.numFound ?? 0,
      start: data.start ?? 0,
      results: (data.docs ?? []).map((d) => ({
        work_id: d.key?.replace(/^\/works\//, '') ?? null,
        title: d.title ?? null,
        authors: (d.author_name ?? []).map((name, i) => ({
          name,
          author_id: d.author_key?.[i]?.replace(/^\/authors\//, '') ?? null,
        })),
        first_publish_year: d.first_publish_year ?? null,
        edition_count: d.edition_count ?? null,
        isbn_sample: (d.isbn ?? []).slice(0, 5),
        languages: d.language ?? [],
        subjects: (d.subject ?? []).slice(0, 10),
        ratings_average: d.ratings_average ?? null,
        cover_url: this.coverUrl(d.cover_i),
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getBookByIsbn(args: Record<string, unknown>): Promise<ToolResult> {
    const isbn = this.reqStr(args, 'isbn', '"9780743273565"');
    const clean = isbn.replace(/[-\s]/g, '');

    const data = await this.olRequest<{
      title?: string;
      authors?: { key?: string }[];
      publishers?: string[];
      publish_date?: string;
      number_of_pages?: number;
      subjects?: string[];
      identifiers?: Record<string, string[]>;
      isbn_10?: string[];
      isbn_13?: string[];
      covers?: number[];
      languages?: { key?: string }[];
      works?: { key?: string }[];
    }>(`/isbn/${clean}.json`);

    const result = {
      isbn: clean,
      title: data.title ?? null,
      authors: (data.authors ?? [])
        .map((a) => a.key?.replace(/^\/authors\//, '') ?? null)
        .filter(Boolean),
      publishers: data.publishers ?? [],
      publish_date: data.publish_date ?? null,
      pages: data.number_of_pages ?? null,
      subjects: data.subjects ?? [],
      identifiers: data.identifiers ?? {},
      isbn_10: data.isbn_10 ?? [],
      isbn_13: data.isbn_13 ?? [],
      languages: (data.languages ?? [])
        .map((l) => l.key?.replace(/^\/languages\//, '') ?? null)
        .filter(Boolean),
      work_ids: (data.works ?? [])
        .map((w) => w.key?.replace(/^\/works\//, '') ?? null)
        .filter(Boolean),
      cover_url: this.coverUrl(data.covers?.[0]),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getWork(args: Record<string, unknown>): Promise<ToolResult> {
    const workId = this.reqStr(args, 'work_id', '"OL45804W"');
    const clean = workId.replace(/^\/works\//, '');

    const data = await this.olRequest<{
      key?: string;
      title?: string;
      description?: string | { value?: string };
      subjects?: string[];
      subject_places?: string[];
      subject_people?: string[];
      subject_times?: string[];
      first_publish_date?: string;
      authors?: { author?: { key?: string }; type?: { key?: string } }[];
      covers?: number[];
    }>(`/works/${clean}.json`);

    const desc =
      typeof data.description === 'string'
        ? data.description
        : data.description?.value ?? null;

    const result = {
      work_id: data.key?.replace(/^\/works\//, '') ?? clean,
      title: data.title ?? null,
      description: desc,
      first_publish_date: data.first_publish_date ?? null,
      authors: (data.authors ?? [])
        .map((a) => a.author?.key?.replace(/^\/authors\//, '') ?? null)
        .filter(Boolean),
      subjects: data.subjects ?? [],
      subject_places: data.subject_places ?? [],
      subject_people: data.subject_people ?? [],
      subject_times: data.subject_times ?? [],
      cover_url: this.coverUrl(data.covers?.[0]),
      open_library_url: `${BASE_URL}/works/${clean}`,
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getAuthor(args: Record<string, unknown>): Promise<ToolResult> {
    const authorId = this.reqStr(args, 'author_id', '"OL34184A"');
    const clean = authorId.replace(/^\/authors\//, '');

    const data = await this.olRequest<{
      key?: string;
      name?: string;
      personal_name?: string;
      alternate_names?: string[];
      bio?: string | { value?: string };
      birth_date?: string;
      death_date?: string;
      photos?: number[];
      wikipedia?: string;
      links?: { url?: string; title?: string }[];
    }>(`/authors/${clean}.json`);

    const bio =
      typeof data.bio === 'string' ? data.bio : data.bio?.value ?? null;

    const result = {
      author_id: data.key?.replace(/^\/authors\//, '') ?? clean,
      name: data.name ?? null,
      personal_name: data.personal_name ?? null,
      alternate_names: data.alternate_names ?? [],
      bio,
      birth_date: data.birth_date ?? null,
      death_date: data.death_date ?? null,
      wikipedia: data.wikipedia ?? null,
      links: data.links ?? [],
      photo_url: data.photos?.[0]
        ? `${COVERS_URL}/a/id/${data.photos[0]}-L.jpg`
        : null,
      open_library_url: `${BASE_URL}/authors/${clean}`,
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
