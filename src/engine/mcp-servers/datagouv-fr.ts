/**
 * data.gouv.fr MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream API: https://www.data.gouv.fr/api/1
// Auth: none — public read API
// Docs: https://www.data.gouv.fr/dataservices/api/
// Category: data
// Rate limits: none documented for public read

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://www.data.gouv.fr/api/1';
const USER_AGENT = 'epic-ai-chariot/1.0';

export class DataGouvFrMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('DataGouvFrMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'datagouv-fr',
      displayName: 'data.gouv.fr — French Open Data',
      version: '1.0.0',
      category: 'data',
      keywords: [
        'datagouv', 'data.gouv.fr', 'france', 'french', 'open data',
        'datasets', 'government data', 'public data', 'organizations',
        'reuses', 'catalogue', 'etalab', 'resources',
      ],
      toolNames: [
        'search_datasets',
        'dataset',
        'resources',
        'search_organizations',
        'organization',
        'reuses_search',
      ],
      description: 'data.gouv.fr API: search and retrieve datasets, resources, organizations, and reuses from the French government open-data catalogue.',
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
        name: 'search_datasets',
        description: 'Search datasets on data.gouv.fr.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Full-text search query.' },
            organization: { type: 'string', description: 'Filter by organization id or slug.' },
            tag: { type: 'string', description: 'Filter by tag.' },
            page: { type: 'number', description: '1-based page number (default 1).' },
            page_size: { type: 'number', description: 'Results per page, 1-200 (default 20).' },
          },
        },
      },
      {
        name: 'dataset',
        description: 'Retrieve a single dataset by id or slug from data.gouv.fr.',
        inputSchema: {
          type: 'object',
          properties: {
            id_or_slug: { type: 'string', description: 'Dataset id or slug.' },
          },
          required: ['id_or_slug'],
        },
      },
      {
        name: 'resources',
        description: 'List downloadable resources (files) attached to a dataset on data.gouv.fr.',
        inputSchema: {
          type: 'object',
          properties: {
            dataset_id_or_slug: { type: 'string', description: 'Dataset id or slug.' },
          },
          required: ['dataset_id_or_slug'],
        },
      },
      {
        name: 'search_organizations',
        description: 'Search organizations on data.gouv.fr.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Full-text search query.' },
            page: { type: 'number', description: '1-based page number (default 1).' },
            page_size: { type: 'number', description: 'Results per page, 1-200 (default 20).' },
          },
        },
      },
      {
        name: 'organization',
        description: 'Retrieve a single organization by id or slug from data.gouv.fr.',
        inputSchema: {
          type: 'object',
          properties: {
            id_or_slug: { type: 'string', description: 'Organization id or slug.' },
          },
          required: ['id_or_slug'],
        },
      },
      {
        name: 'reuses_search',
        description: 'Search reuses (apps and analyses built on top of datasets) on data.gouv.fr.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Full-text search query.' },
            page: { type: 'number', description: '1-based page number (default 1).' },
            page_size: { type: 'number', description: 'Results per page, 1-200 (default 20).' },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_datasets':    return this.searchDatasets(args);
        case 'dataset':            return this.getDataset(args);
        case 'resources':          return this.getResources(args);
        case 'search_organizations': return this.searchOrganizations(args);
        case 'organization':       return this.getOrganization(args);
        case 'reuses_search':      return this.searchReuses(args);
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

  private buildSearchParams(args: Record<string, unknown>): URLSearchParams {
    const p = new URLSearchParams();
    if (args.query) p.set('q', String(args.query));
    p.set('page', String(Math.max(1, Number(args.page ?? 1))));
    p.set('page_size', String(Math.min(200, Math.max(1, Number(args.page_size ?? 20)))));
    return p;
  }

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }

  private async dgGet(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': USER_AGENT,
      },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'data.gouv.fr: not found' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `data.gouv.fr: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchDatasets(args: Record<string, unknown>): Promise<ToolResult> {
    const params = this.buildSearchParams(args);
    if (args.organization) params.set('organization', String(args.organization));
    if (args.tag) params.set('tag', String(args.tag));
    return this.dgGet(`/datasets/?${params}`);
  }

  private async getDataset(args: Record<string, unknown>): Promise<ToolResult> {
    const slug = this.requireString(args, 'id_or_slug', '"my-dataset-slug"');
    return this.dgGet(`/datasets/${encodeURIComponent(slug)}/`);
  }

  private async getResources(args: Record<string, unknown>): Promise<ToolResult> {
    const slug = this.requireString(args, 'dataset_id_or_slug', '"my-dataset-slug"');
    return this.dgGet(`/datasets/${encodeURIComponent(slug)}/resources/`);
  }

  private async searchOrganizations(args: Record<string, unknown>): Promise<ToolResult> {
    return this.dgGet(`/organizations/?${this.buildSearchParams(args)}`);
  }

  private async getOrganization(args: Record<string, unknown>): Promise<ToolResult> {
    const slug = this.requireString(args, 'id_or_slug', '"my-org-slug"');
    return this.dgGet(`/organizations/${encodeURIComponent(slug)}/`);
  }

  private async searchReuses(args: Record<string, unknown>): Promise<ToolResult> {
    return this.dgGet(`/reuses/?${this.buildSearchParams(args)}`);
  }
}
