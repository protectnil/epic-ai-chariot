/**
 * Wikipedia MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official MCP: None found as of 2026-03.
// No official Wikipedia / Wikimedia Foundation MCP server exists on GitHub.
// We build a REST wrapper covering the English Wikipedia REST API v1.
//
// Base URL: https://en.wikipedia.org/api/rest_v1
// Auth: None required for read operations. User-Agent header recommended.
// Docs: https://en.wikipedia.org/api/rest_v1/#/
// Rate limits: ~200 req/s per IP; please set a descriptive User-Agent.
// Note: This adapter covers the public read-only endpoints accessible without auth,
//       scoped exclusively to en.wikipedia.org (not other Wikimedia projects).

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface WikipediaConfig {
  /** Optional base URL override (default: https://en.wikipedia.org/api/rest_v1) */
  baseUrl?: string;
  /** User-Agent string sent with every request — set to identify your application */
  userAgent?: string;
}

export class WikipediaMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;
  private readonly userAgent: string;

  constructor(config: WikipediaConfig = {}) {
    super();
    this.baseUrl   = config.baseUrl   ?? 'https://en.wikipedia.org/api/rest_v1';
    this.userAgent = config.userAgent ?? 'EpicAI-WikipediaAdapter/1.0 (https://protectnil.com)';
  }

  static catalog() {
    return {
      name: 'wikipedia',
      displayName: 'Wikipedia',
      version: '1.0.0',
      category: 'reference',
      keywords: [
        'wikipedia', 'wiki', 'article', 'page', 'summary', 'content',
        'media', 'html', 'wikitext', 'revision', 'citation',
        'encyclopedia', 'knowledge', 'reference', 'open-source', 'mobile',
        'media-list',
      ],
      toolNames: [
        'get_page_summary',
        'get_page_html',
        'get_page_media_list',
        'get_page_mobile_html',
        'get_revision_metadata',
        'get_citation',
        'get_mobile_css',
      ],
      description: 'English Wikipedia REST API: fetch article summaries, HTML content, media lists, mobile-optimised pages, revision metadata, and citation data.',
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'get_page_summary',
        description: 'Get basic metadata and a simplified article introduction (plain-text extract, thumbnail, coordinates) for an English Wikipedia title — the fastest way to get an article overview',
        inputSchema: {
          type: 'object',
          properties: {
            title: {
              type: 'string',
              description: 'Wikipedia article title (e.g. "Albert_Einstein", "Mount_Everest"). Use underscores instead of spaces.',
            },
            redirect: {
              type: 'boolean',
              description: 'Follow page redirects (default: true). Set false to disable.',
            },
            acceptLanguage: {
              type: 'string',
              description: 'BCP-47 language code for the response language (e.g. "en-US"). Defaults to English.',
            },
          },
          required: ['title'],
        },
      },
      {
        name: 'get_page_html',
        description: 'Get the latest fully-rendered HTML for an English Wikipedia article — suitable for parsing structured content, infoboxes, and tables',
        inputSchema: {
          type: 'object',
          properties: {
            title: {
              type: 'string',
              description: 'Wikipedia article title (e.g. "Solar_system"). Use underscores instead of spaces.',
            },
            revision: {
              type: 'number',
              description: 'Specific revision ID to retrieve (omit for the latest revision)',
            },
            redirect: {
              type: 'boolean',
              description: 'Follow page redirects (default: true)',
            },
          },
          required: ['title'],
        },
      },
      {
        name: 'get_page_media_list',
        description: 'Get the list of all media files (images, audio, video) used on an English Wikipedia page — returns file names, captions, and section context',
        inputSchema: {
          type: 'object',
          properties: {
            title: {
              type: 'string',
              description: 'Wikipedia article title (e.g. "Eiffel_Tower"). Use underscores instead of spaces.',
            },
            revision: {
              type: 'number',
              description: 'Specific revision ID to retrieve media list for (omit for latest)',
            },
            redirect: {
              type: 'boolean',
              description: 'Follow page redirects (default: true)',
            },
          },
          required: ['title'],
        },
      },
      {
        name: 'get_page_mobile_html',
        description: 'Get mobile-optimised HTML for an English Wikipedia article — stripped-down content suitable for rendering on small screens or in mobile apps',
        inputSchema: {
          type: 'object',
          properties: {
            title: {
              type: 'string',
              description: 'Wikipedia article title (e.g. "Python_(programming_language)"). Use underscores instead of spaces.',
            },
            revision: {
              type: 'number',
              description: 'Specific revision ID to retrieve (omit for latest)',
            },
            redirect: {
              type: 'boolean',
              description: 'Follow page redirects (default: true)',
            },
          },
          required: ['title'],
        },
      },
      {
        name: 'get_revision_metadata',
        description: 'Get revision metadata for an English Wikipedia title — includes revision ID, timestamp, user, size delta, and tags for the latest or a specific revision',
        inputSchema: {
          type: 'object',
          properties: {
            title: {
              type: 'string',
              description: 'Wikipedia article title (e.g. "Quantum_computing"). Use underscores instead of spaces.',
            },
            revision: {
              type: 'number',
              description: 'Specific revision ID (omit to get metadata for the latest revision)',
            },
          },
          required: ['title'],
        },
      },
      {
        name: 'get_citation',
        description: 'Get citation data for an article identifier (DOI, PMID, ISBN, URL, etc.) in a given format — returns structured bibliographic metadata',
        inputSchema: {
          type: 'object',
          properties: {
            format: {
              type: 'string',
              description: 'Output citation format: "mediawiki", "mediawiki-basefields", "zotero", "bibtex", or "wikibase"',
            },
            query: {
              type: 'string',
              description: 'Article identifier — DOI (e.g. "10.1038/nature12373"), PMID (e.g. "pmid:23907271"), ISBN, or URL',
            },
            acceptLanguage: {
              type: 'string',
              description: 'BCP-47 language code for metadata (e.g. "en-US")',
            },
          },
          required: ['format', 'query'],
        },
      },
      {
        name: 'get_mobile_css',
        description: 'Get the CSS stylesheet used by Wikimedia mobile apps for a given type — useful for matching the Wikipedia mobile look and feel',
        inputSchema: {
          type: 'object',
          properties: {
            type: {
              type: 'string',
              description: 'CSS type: "base", "site", or "mobile" (base = core Wikipedia styles, site = site-specific, mobile = mobile overrides)',
            },
          },
          required: ['type'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_page_summary':                return this.getPageSummary(args);
        case 'get_page_html':                   return this.getPageHtml(args);
        case 'get_page_media_list':             return this.getPageMediaList(args);
        case 'get_page_mobile_html':            return this.getPageMobileHtml(args);
        case 'get_revision_metadata':           return this.getRevisionMetadata(args);
        case 'get_citation':                    return this.getCitation(args);
        case 'get_mobile_css':                  return this.getMobileCss(args);
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

  private async get(path: string, params: Record<string, string> = {}): Promise<ToolResult> {
    const qs = Object.keys(params).length > 0 ? '?' + new URLSearchParams(params).toString() : '';
    const response = await this.fetchWithRetry(`${this.baseUrl}${path}${qs}`, {
      headers: {
        'User-Agent': this.userAgent,
        'Accept': 'application/json',
      },
    });
    if (!response.ok) {
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${response.statusText}` }],
        isError: true,
      };
    }
    const data: unknown = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getText(path: string, params: Record<string, string> = {}): Promise<ToolResult> {
    const qs = Object.keys(params).length > 0 ? '?' + new URLSearchParams(params).toString() : '';
    const response = await this.fetchWithRetry(`${this.baseUrl}${path}${qs}`, {
      headers: {
        'User-Agent': this.userAgent,
        'Accept': 'text/html',
      },
    });
    if (!response.ok) {
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${response.statusText}` }],
        isError: true,
      };
    }
    const text = await response.text();
    return { content: [{ type: 'text', text: this.truncate(text) }], isError: false };
  }

  // ── Tool implementations ─────────────────────────────────────────────────────

  private async getPageSummary(args: Record<string, unknown>): Promise<ToolResult> {
    const title = args['title'] as string | undefined;
    if (!title) {
      return { content: [{ type: 'text', text: 'title is required' }], isError: true };
    }
    const params: Record<string, string> = {};
    if (args['redirect'] === false) params['redirect'] = 'false';
    const headers: Record<string, string> = {};
    if (typeof args['acceptLanguage'] === 'string') headers['Accept-Language'] = args['acceptLanguage'];
    const qs = Object.keys(params).length > 0 ? '?' + new URLSearchParams(params).toString() : '';
    const response = await this.fetchWithRetry(`${this.baseUrl}/page/summary/${encodeURIComponent(title)}${qs}`, {
      headers: {
        'User-Agent': this.userAgent,
        'Accept': 'application/json',
        ...headers,
      },
    });
    if (!response.ok) {
      return { content: [{ type: 'text', text: `API error: ${response.status} ${response.statusText}` }], isError: true };
    }
    const data: unknown = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getPageHtml(args: Record<string, unknown>): Promise<ToolResult> {
    const title = args['title'] as string | undefined;
    if (!title) {
      return { content: [{ type: 'text', text: 'title is required' }], isError: true };
    }
    const revision = args['revision'] as number | undefined;
    const path = revision
      ? `/page/html/${encodeURIComponent(title)}/${revision}`
      : `/page/html/${encodeURIComponent(title)}`;
    const params: Record<string, string> = {};
    if (args['redirect'] === false) params['redirect'] = 'false';
    return this.getText(path, params);
  }

  private async getPageMediaList(args: Record<string, unknown>): Promise<ToolResult> {
    const title = args['title'] as string | undefined;
    if (!title) {
      return { content: [{ type: 'text', text: 'title is required' }], isError: true };
    }
    const revision = args['revision'] as number | undefined;
    const path = revision
      ? `/page/media-list/${encodeURIComponent(title)}/${revision}`
      : `/page/media-list/${encodeURIComponent(title)}`;
    const params: Record<string, string> = {};
    if (args['redirect'] === false) params['redirect'] = 'false';
    return this.get(path, params);
  }

  private async getPageMobileHtml(args: Record<string, unknown>): Promise<ToolResult> {
    const title = args['title'] as string | undefined;
    if (!title) {
      return { content: [{ type: 'text', text: 'title is required' }], isError: true };
    }
    const revision = args['revision'] as number | undefined;
    const path = revision
      ? `/page/mobile-html/${encodeURIComponent(title)}/${revision}`
      : `/page/mobile-html/${encodeURIComponent(title)}`;
    const params: Record<string, string> = {};
    if (args['redirect'] === false) params['redirect'] = 'false';
    return this.getText(path, params);
  }

  private async getRevisionMetadata(args: Record<string, unknown>): Promise<ToolResult> {
    const title = args['title'] as string | undefined;
    if (!title) {
      return { content: [{ type: 'text', text: 'title is required' }], isError: true };
    }
    const revision = args['revision'] as number | undefined;
    const path = revision
      ? `/page/title/${encodeURIComponent(title)}/${revision}`
      : `/page/title/${encodeURIComponent(title)}`;
    return this.get(path);
  }

  private async getCitation(args: Record<string, unknown>): Promise<ToolResult> {
    const format = args['format'] as string | undefined;
    const query  = args['query']  as string | undefined;
    if (!format || !query) {
      return { content: [{ type: 'text', text: 'format and query are required' }], isError: true };
    }
    const headers: Record<string, string> = {};
    if (typeof args['acceptLanguage'] === 'string') headers['Accept-Language'] = args['acceptLanguage'];
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/data/citation/${encodeURIComponent(format)}/${encodeURIComponent(query)}`,
      {
        headers: {
          'User-Agent': this.userAgent,
          'Accept': 'application/json',
          ...headers,
        },
      },
    );
    if (!response.ok) {
      return { content: [{ type: 'text', text: `API error: ${response.status} ${response.statusText}` }], isError: true };
    }
    const data: unknown = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getMobileCss(args: Record<string, unknown>): Promise<ToolResult> {
    const type = args['type'] as string | undefined;
    if (!type) {
      return { content: [{ type: 'text', text: 'type is required' }], isError: true };
    }
    return this.getText(`/data/css/mobile/${encodeURIComponent(type)}`);
  }
}
