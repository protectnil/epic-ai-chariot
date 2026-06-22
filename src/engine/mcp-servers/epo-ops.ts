/**
 * EPO Open Patent Services (OPS) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL : https://ops.epo.org/3.2/rest-services/
 * Auth     : OAuth2 client_credentials — token from https://ops.epo.org/3.2/auth/accesstoken
 * Docs     : https://developers.epo.org/
 * Free tier: 4 GB/week download quota; rate-limited to 10 req/min
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const TOKEN_URL = 'https://ops.epo.org/3.2/auth/accesstoken';
const BASE_URL  = 'https://ops.epo.org/3.2/rest-services';
const TOKEN_TTL_MS = 18 * 60 * 1000; // refresh slightly before EPO's 20-min lifetime

interface EpoOpsConfig {
  /** EPO OPS consumer key + secret joined as "key:secret" */
  apiKey: string;
  baseUrl?: string;
}

interface CachedToken {
  access_token: string;
  expires_at: number;
}

export class EpoOpsMCPServer extends MCPAdapterBase {
  private readonly consumerKey: string;
  private readonly consumerSecret: string;
  private readonly baseUrl: string;
  private readonly tokenCache = new Map<string, CachedToken>();

  constructor(config: EpoOpsConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('EPO OPS: configuration object is required');
    }
    if (!config.apiKey || typeof config.apiKey !== 'string' || !config.apiKey.trim()) {
      throw new Error('EPO OPS: apiKey is required (format: "consumer_key:consumer_secret")');
    }
    const colon = config.apiKey.indexOf(':');
    if (colon < 1 || colon === config.apiKey.length - 1) {
      throw new Error('EPO OPS: apiKey must be "consumer_key:consumer_secret"');
    }
    this.consumerKey    = config.apiKey.slice(0, colon);
    this.consumerSecret = config.apiKey.slice(colon + 1);
    this.baseUrl = config.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'epo-ops',
      displayName: 'EPO Open Patent Services',
      version: '1.0.0',
      category: 'legal' as const,
      keywords: [
        'epo', 'patent', 'patents', 'ops', 'open patent services',
        'intellectual property', 'ip', 'inpadoc', 'patent search',
        'patent family', 'patent claims', 'patent abstract', 'bibliographic',
        'cql', 'epodoc', 'inventors', 'applicants', 'prior art',
      ],
      toolNames: [
        'search_patents',
        'get_biblio',
        'get_family',
        'get_abstract',
        'get_claims',
      ],
      description: 'EPO Open Patent Services (OPS): search published patents via CQL, retrieve bibliographic data, INPADOC patent families, abstracts, and claims. Auth: OAuth2 client credentials (consumer_key:consumer_secret).',
      type: 'rest' as const,
      auth: {
        inferredModel: 'oauth2' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil' as const,
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'search_patents',
        description:
          'Search published patents using CQL (EPO Common Query Language). Returns a paginated list of publication numbers matching the query. Example queries: "ta=hydrogen", "in=Tesla", "pa=apple", "txt=neural network AND pd>=2020".',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description:
                'EPO CQL — fields: ta (title-abstract), ti (title), ab (abstract), txt (any text), in (inventor), pa (applicant), cl (classification), pn (publication number), ap (application number), pr (priority), pd (publication date), ad (application date).',
            },
            range: {
              type: 'string',
              description: 'Result range "start-end" (1-indexed). Max 100 per page. Default "1-25".',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_biblio',
        description:
          'Bibliographic data for a patent — title, inventors, applicants, dates, classifications.',
        inputSchema: {
          type: 'object',
          properties: {
            number: {
              type: 'string',
              description: 'Patent number in epodoc format, e.g. "EP1234567"',
            },
          },
          required: ['number'],
        },
      },
      {
        name: 'get_family',
        description:
          'INPADOC family — related patent applications worldwide for the same underlying invention.',
        inputSchema: {
          type: 'object',
          properties: {
            number: {
              type: 'string',
              description: 'Patent number in epodoc format, e.g. "EP1234567"',
            },
          },
          required: ['number'],
        },
      },
      {
        name: 'get_abstract',
        description: 'Abstract text for a patent.',
        inputSchema: {
          type: 'object',
          properties: {
            number: {
              type: 'string',
              description: 'Patent number in epodoc format, e.g. "EP1234567"',
            },
          },
          required: ['number'],
        },
      },
      {
        name: 'get_claims',
        description: 'Claims text for a patent.',
        inputSchema: {
          type: 'object',
          properties: {
            number: {
              type: 'string',
              description: 'Patent number in epodoc format, e.g. "EP1234567"',
            },
          },
          required: ['number'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_patents': return this.searchPatents(args);
        case 'get_biblio':    return this.getPublishedData(args, 'biblio');
        case 'get_family':    return this.getFamily(args);
        case 'get_abstract':  return this.getPublishedData(args, 'abstract');
        case 'get_claims':    return this.getPublishedData(args, 'claims');
        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (error) {
      return {
        content: [{ type: 'text', text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true,
      };
    }
  }

  // ── OAuth2 token management ────────────────────────────────────────────────

  private async getAccessToken(): Promise<string> {
    const cached = this.tokenCache.get(this.consumerKey);
    if (cached && cached.expires_at > Date.now()) return cached.access_token;

    const basic = Buffer.from(`${this.consumerKey}:${this.consumerSecret}`).toString('base64');
    const response = await this.fetchWithRetry(TOKEN_URL, {
      method: 'POST',
      headers: {
        Authorization: `Basic ${basic}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: 'grant_type=client_credentials',
    });

    if (!response.ok) {
      const text = await response.text().catch(() => response.statusText);
      throw new Error(`EPO OAuth: ${response.status} ${text.slice(0, 200)}`);
    }

    const data = (await response.json()) as { access_token?: string; expires_in?: string | number };
    if (!data.access_token) {
      throw new Error('EPO OAuth: response missing access_token');
    }

    const ttl = (Number(data.expires_in) || 1200) * 1000;
    this.tokenCache.set(this.consumerKey, {
      access_token: data.access_token,
      expires_at: Date.now() + Math.min(ttl, TOKEN_TTL_MS),
    });
    return data.access_token;
  }

  // ── Tool implementations ───────────────────────────────────────────────────

  private async searchPatents(args: Record<string, unknown>): Promise<ToolResult> {
    const query = this.requireString(args, 'query');
    const range = typeof args.range === 'string' ? args.range : '1-25';
    const token = await this.getAccessToken();

    const params = new URLSearchParams({ q: query });
    const url = `${this.baseUrl}/published-data/search?${params}`;

    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        'X-OPS-Range': range,
      },
    });

    if (!response.ok) {
      const text = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `EPO error: ${response.status} ${text.slice(0, 200)}` }],
        isError: true,
      };
    }

    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getPublishedData(
    args: Record<string, unknown>,
    constituent: 'biblio' | 'abstract' | 'claims',
  ): Promise<ToolResult> {
    const number = this.requireString(args, 'number');
    const token  = await this.getAccessToken();
    const path   = `/published-data/publication/epodoc/${encodeURIComponent(number)}/${constituent}`;

    return this.epoGet(token, path);
  }

  private async getFamily(args: Record<string, unknown>): Promise<ToolResult> {
    const number = this.requireString(args, 'number');
    const token  = await this.getAccessToken();
    const path   = `/family/publication/epodoc/${encodeURIComponent(number)}`;

    return this.epoGet(token, path);
  }

  private async epoGet(token: string, path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
      },
    });

    if (!response.ok) {
      const text = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `EPO error: ${response.status} ${text.slice(0, 200)}` }],
        isError: true,
      };
    }

    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  // ── Utilities ──────────────────────────────────────────────────────────────

  private requireString(args: Record<string, unknown>, key: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty.`);
    }
    return v;
  }
}
