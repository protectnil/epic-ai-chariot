/**
 * Open Library Books API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream confirmed from open-source MCP wrapper (MIT) for the Open Library API.
// This file calls the real upstream directly. No proxy or gateway is involved.
//
// Base URL: https://openlibrary.org
// Auth: None required — Open Library API is public and free with no auth.
// Docs: https://openlibrary.org/developers/api
// Rate limits: None officially documented; polite use expected.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface BooksConfig {
  /** Optional base URL override (default: https://openlibrary.org) */
  baseUrl?: string;
}

export class BooksMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config: BooksConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Open Library Books API: configuration object is required');
    }
    this.baseUrl = config.baseUrl ?? 'https://openlibrary.org';
  }

  static catalog() {
    return {
      name: 'books',
      displayName: 'Open Library Books API',
      version: '1.0.0',
      category: 'data',
      keywords: [
        'books', 'open library', 'isbn', 'author', 'search books',
        'book details', 'bibliography', 'literature', 'library',
        'publishing', 'free', 'public api', 'internet archive',
      ],
      toolNames: ['search_books', 'get_book', 'get_author'],
      description: 'Open Library Books API: search for books by title, author, or keyword; retrieve full book details by ISBN; and look up author biographies — all free and unauthenticated via openlibrary.org.',
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
        description: 'Search for books by title, author, or keyword. Returns title, author, year, ISBN, and cover image URL.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query (title, author, or keywords)',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (1–20, default 5)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_book',
        description: 'Get full details for a book by ISBN.',
        inputSchema: {
          type: 'object',
          properties: {
            isbn: {
              type: 'string',
              description: 'ISBN-10 or ISBN-13',
            },
          },
          required: ['isbn'],
        },
      },
      {
        name: 'get_author',
        description: 'Get biography and key info for an author using their Open Library author key (e.g., "OL23919A").',
        inputSchema: {
          type: 'object',
          properties: {
            author_key: {
              type: 'string',
              description: 'Open Library author key (e.g., OL23919A)',
            },
          },
          required: ['author_key'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_books': return this.searchBooks(args);
        case 'get_book':     return this.getBook(args);
        case 'get_author':   return this.getAuthor(args);
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

  private async searchBooks(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const limitRaw = typeof args.limit === 'number' ? args.limit : 5;
    const limit = Math.min(20, Math.max(1, limitRaw));
    const params = new URLSearchParams({ q: query, limit: String(limit) });
    const url = `${this.baseUrl}/search.json?${params.toString()}`;

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

    const data = (await response.json()) as {
      numFound: number;
      docs: Array<{
        title: string;
        author_name?: string[];
        first_publish_year?: number;
        isbn?: string[];
        cover_i?: number;
        key: string;
        number_of_pages_median?: number;
        subject?: string[];
      }>;
    };

    const result = {
      total_found: data.numFound,
      books: data.docs.map((doc) => ({
        title: doc.title,
        authors: doc.author_name ?? [],
        first_published: doc.first_publish_year ?? null,
        isbn: doc.isbn?.[0] ?? null,
        cover_url: doc.cover_i
          ? `https://covers.openlibrary.org/b/id/${doc.cover_i}-M.jpg`
          : null,
        open_library_key: doc.key,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getBook(args: Record<string, unknown>): Promise<ToolResult> {
    const cleanIsbn = (args.isbn as string).replace(/[^0-9X]/gi, '');
    const url = `${this.baseUrl}/isbn/${encodeURIComponent(cleanIsbn)}.json`;

    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: `Book not found for ISBN: "${args.isbn}"` }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      title: string;
      authors?: { key: string }[];
      publish_date?: string;
      number_of_pages?: number;
      subjects?: string[];
      description?: string | { value: string };
      covers?: number[];
    };

    const description =
      typeof data.description === 'string'
        ? data.description
        : data.description?.value ?? null;

    const result = {
      title: data.title,
      publish_date: data.publish_date ?? null,
      number_of_pages: data.number_of_pages ?? null,
      subjects: (data.subjects ?? []).slice(0, 10),
      description,
      cover_url: data.covers?.[0]
        ? `https://covers.openlibrary.org/b/id/${data.covers[0]}-M.jpg`
        : null,
      author_keys: (data.authors ?? []).map((a) => a.key.replace('/authors/', '')),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getAuthor(args: Record<string, unknown>): Promise<ToolResult> {
    const key = (args.author_key as string).replace(/^\/authors\//, '');
    const url = `${this.baseUrl}/authors/${encodeURIComponent(key)}.json`;

    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: `Author not found: "${args.author_key}"` }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      name: string;
      birth_date?: string;
      death_date?: string;
      bio?: string | { value: string };
      wikipedia?: string;
    };

    const bio =
      typeof data.bio === 'string' ? data.bio : data.bio?.value ?? null;

    const result = {
      name: data.name,
      birth_date: data.birth_date ?? null,
      death_date: data.death_date ?? null,
      bio,
      wikipedia_url: data.wikipedia ?? null,
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
