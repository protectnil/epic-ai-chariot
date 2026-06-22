/**
 * Tatoeba MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://tatoeba.org/en/api_v0
// Auth: none (public corpus)
// Docs: https://en.wiki.tatoeba.org/articles/show/api
// Category: language
// Rate limits: none documented; be polite
// Note: api_v0 has only /search and /sentence/{id} endpoints.
//       Language list is extracted from the languages-json attribute
//       embedded in https://tatoeba.org/en/sentences/search page HTML.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://tatoeba.org/en/api_v0';
const SEARCH_PAGE_URL = 'https://tatoeba.org/en/sentences/search?query=hello';

export class TatoebaMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('TatoebaMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'tatoeba',
      displayName: 'Tatoeba',
      version: '1.0.0',
      category: 'language',
      keywords: [
        'tatoeba', 'sentences', 'multilingual', 'translations', 'corpus',
        'language learning', 'linguistics', 'iso 639-3', 'parallel corpus',
      ],
      toolNames: ['search', 'sentence', 'translations', 'languages'],
      description: 'Tatoeba multilingual sentence corpus: search sentences, fetch single sentences by ID, retrieve translations, and list supported languages.',
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
        name: 'search',
        description: 'Search sentences in the Tatoeba corpus. Use ISO 639-3 language codes (e.g. "eng", "fra", "spa", "jpn", "cmn") for the from/to parameters.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query string.',
            },
            from: {
              type: 'string',
              description: 'Source language ISO 639-3 code (default: any).',
            },
            to: {
              type: 'string',
              description: 'Target translation language ISO 639-3 code (default: any).',
            },
            page: {
              type: 'number',
              description: '1-based page number (default: 1).',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return, 1–100 (default: 25).',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'sentence',
        description: 'Retrieve a single Tatoeba sentence by its numeric ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Numeric sentence ID.',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'translations',
        description: 'Retrieve all available translations for a Tatoeba sentence by its numeric ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Numeric sentence ID.',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'languages',
        description: 'List all languages supported by the Tatoeba corpus.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search':       return this.search(args);
        case 'sentence':     return this.getSentence(args);
        case 'translations': return this.getTranslations(args);
        case 'languages':    return this.getLanguages();
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

  private async get(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'Tatoeba: not found' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Tatoeba API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query;
    if (typeof query !== 'string' || !query.trim()) {
      return {
        content: [{ type: 'text', text: 'Required argument "query" is missing or empty.' }],
        isError: true,
      };
    }

    const params = new URLSearchParams({
      query: query.trim(),
      page: String(Math.max(1, typeof args.page === 'number' ? args.page : 1)),
    });
    if (args.from && typeof args.from === 'string') params.set('from', args.from);
    if (args.to && typeof args.to === 'string') params.set('to', args.to);

    const limit = typeof args.limit === 'number'
      ? Math.min(100, Math.max(1, args.limit))
      : 25;

    const result = await this.get(`/search?${params.toString()}`);
    if (result.isError) return result;

    // Apply client-side limit to results array
    try {
      const parsed = JSON.parse(result.content[0].text) as { results?: unknown[]; paging?: unknown };
      if (Array.isArray(parsed.results)) {
        parsed.results = parsed.results.slice(0, limit);
      }
      return { content: [{ type: 'text', text: this.truncate(parsed) }], isError: false };
    } catch {
      return result;
    }
  }

  private async getSentence(args: Record<string, unknown>): Promise<ToolResult> {
    const id = typeof args.id === 'number' ? (args.id | 0) : parseInt(String(args.id), 10);
    if (!Number.isFinite(id)) {
      return { content: [{ type: 'text', text: 'Required argument "id" must be a numeric sentence ID.' }], isError: true };
    }
    return this.get(`/sentence/${id}`);
  }

  private async getTranslations(args: Record<string, unknown>): Promise<ToolResult> {
    const id = typeof args.id === 'number' ? (args.id | 0) : parseInt(String(args.id), 10);
    if (!Number.isFinite(id)) {
      return { content: [{ type: 'text', text: 'Required argument "id" must be a numeric sentence ID.' }], isError: true };
    }
    return this.get(`/sentence/${id}/translations`);
  }

  private async getLanguages(): Promise<ToolResult> {
    // api_v0 has no /languages endpoint. The language list (429 entries) is
    // embedded as a `languages-json` HTML attribute in every search page.
    const response = await this.fetchWithRetry(SEARCH_PAGE_URL, {
      method: 'GET',
      headers: { Accept: 'text/html' },
    });
    if (!response.ok) {
      return {
        content: [{ type: 'text', text: `Tatoeba languages fetch failed: ${response.status}` }],
        isError: true,
      };
    }
    const html = await response.text();
    const match = html.match(/languages-json="([^"]+)"/);
    if (!match) {
      return {
        content: [{ type: 'text', text: 'Tatoeba: languages-json attribute not found in page' }],
        isError: true,
      };
    }
    // Unescape HTML entities in the attribute value
    const jsonStr = match[1]
      .replace(/&quot;/g, '"')
      .replace(/&amp;/g, '&')
      .replace(/&#39;/g, "'")
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>');
    let langs: Record<string, string>;
    try {
      langs = JSON.parse(jsonStr) as Record<string, string>;
    } catch {
      return {
        content: [{ type: 'text', text: 'Tatoeba: failed to parse languages-json' }],
        isError: true,
      };
    }
    // Remove the placeholder "none" entry if present
    delete langs['none'];
    const result = Object.entries(langs).map(([code, name]) => ({ code, name }));
    return { content: [{ type: 'text', text: this.truncate({ languages: result, count: result.length }) }], isError: false };
  }
}
