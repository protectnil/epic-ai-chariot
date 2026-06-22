/**
 * NosDéputés.fr MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream API docs: https://www.nosdeputes.fr/api
// Base URL: https://www.nosdeputes.fr/{legislature}
// Auth: none — fully public, no API key required
// Category: government
// Rate limits: unspecified; be courteous

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const DEFAULT_LEGISLATURE = '17';

export class NosdeputesfrMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('NosdeputesfrMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? 'https://www.nosdeputes.fr';
  }

  static catalog() {
    return {
      name: 'nosdeputes-fr',
      displayName: 'NosDéputés.fr — French National Assembly',
      version: '1.0.0',
      category: 'government' as const,
      keywords: [
        'nosdeputes', 'france', 'assemblée nationale', 'deputies', 'french parliament',
        'civic', 'legislation', 'votes', 'interventions', 'questions',
        'political groups', 'legislature', 'open data', 'government',
      ],
      toolNames: [
        'list_deputies',
        'get_deputy',
        'search_interventions',
        'search_questions',
        'list_votes',
        'list_groups',
      ],
      description: 'NosDéputés.fr REST adapter: browse French Assemblée nationale deputies, debate interventions, written/oral questions, recorded votes, and political groups via the NosDéputés.fr public JSON API.',
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
        name: 'list_deputies',
        description: 'List sitting deputies, optionally filtered by group or département.',
        inputSchema: {
          type: 'object',
          properties: {
            active: { type: 'boolean', description: 'Only currently active deputies (default true)' },
            group: { type: 'string', description: 'Group acronym (e.g. "RE", "LFI-NUPES")' },
            departement: { type: 'string', description: 'Département name or code' },
            legislature: { type: 'string', description: 'Legislature number (default current: 17)' },
          },
        },
      },
      {
        name: 'get_deputy',
        description: 'Deputy profile by slug or numeric id.',
        inputSchema: {
          type: 'object',
          properties: {
            slug_or_id: { type: 'string', description: 'NosDéputés slug (e.g. "jean-louis-bourlanges") or numeric id' },
            legislature: { type: 'string', description: 'Legislature number (default current: 17)' },
          },
          required: ['slug_or_id'],
        },
      },
      {
        name: 'search_interventions',
        description: 'Full-text search across debate contributions (interventions) in the assembly.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search terms' },
            deputy_slug: { type: 'string', description: 'Restrict results to a specific deputy slug' },
            date_from: { type: 'string', description: 'Start date filter (YYYY-MM-DD)' },
            date_to: { type: 'string', description: 'End date filter (YYYY-MM-DD)' },
            limit: { type: 'number', description: 'Number of results to return, 1–100 (default 25)' },
            legislature: { type: 'string', description: 'Legislature number (default current: 17)' },
          },
          required: ['query'],
        },
      },
      {
        name: 'search_questions',
        description: 'Search written or oral questions submitted by deputies.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search terms' },
            deputy_slug: { type: 'string', description: 'Restrict results to a specific deputy slug' },
            type: { type: 'string', description: 'Question type: ecrite | orale | au gouvernement' },
            limit: { type: 'number', description: 'Number of results to return, 1–100 (default 25)' },
            legislature: { type: 'string', description: 'Legislature number (default current: 17)' },
          },
        },
      },
      {
        name: 'list_votes',
        description: 'Recent recorded votes, optionally filtered by a specific deputy.',
        inputSchema: {
          type: 'object',
          properties: {
            deputy_slug: { type: 'string', description: 'Filter to votes cast by a specific deputy slug' },
            limit: { type: 'number', description: 'Number of results to return, 1–100 (default 25)' },
            legislature: { type: 'string', description: 'Legislature number (default current: 17)' },
          },
        },
      },
      {
        name: 'list_groups',
        description: 'List political groups (groupes parlementaires) in the assembly.',
        inputSchema: {
          type: 'object',
          properties: {
            legislature: { type: 'string', description: 'Legislature number (default current: 17)' },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_deputies':    return this.listDeputies(args);
        case 'get_deputy':       return this.getDeputy(args);
        case 'search_interventions': return this.searchInterventions(args);
        case 'search_questions': return this.searchQuestions(args);
        case 'list_votes':       return this.listVotes(args);
        case 'list_groups':      return this.listGroups(args);
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

  private legBase(legislature?: unknown): string {
    const leg = typeof legislature === 'string' && legislature.trim()
      ? legislature.trim()
      : DEFAULT_LEGISLATURE;
    return `${this.baseUrl}/${encodeURIComponent(leg)}`;
  }

  private async ndRequest(url: string): Promise<ToolResult> {
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': 'epicai-chariot/1.0 (+https://epic-ai.com)',
      },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'NosDéputés: not found (404)' }], isError: true };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NosDéputés error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async listDeputies(args: Record<string, unknown>): Promise<ToolResult> {
    const base = this.legBase(args.legislature);
    const params = new URLSearchParams();
    if (args.active === false) params.set('actifs', '0');
    if (typeof args.group === 'string' && args.group) params.set('groupe', args.group);
    if (typeof args.departement === 'string' && args.departement) params.set('departement', args.departement);
    const qs = params.toString();
    return this.ndRequest(`${base}/deputes/json${qs ? `?${qs}` : ''}`);
  }

  private async getDeputy(args: Record<string, unknown>): Promise<ToolResult> {
    if (typeof args.slug_or_id !== 'string' || !args.slug_or_id.trim()) {
      return {
        content: [{ type: 'text', text: 'Required argument "slug_or_id" is missing. Pass a string like "jean-louis-bourlanges".' }],
        isError: true,
      };
    }
    const base = this.legBase(args.legislature);
    return this.ndRequest(`${base}/${encodeURIComponent(args.slug_or_id.trim())}/json`);
  }

  private async searchInterventions(args: Record<string, unknown>): Promise<ToolResult> {
    if (typeof args.query !== 'string' || !args.query.trim()) {
      return {
        content: [{ type: 'text', text: 'Required argument "query" is missing.' }],
        isError: true,
      };
    }
    const base = this.legBase(args.legislature);
    const limit = typeof args.limit === 'number'
      ? Math.min(100, Math.max(1, args.limit))
      : 25;
    const params = new URLSearchParams({
      recherche: args.query.trim(),
      format: 'json',
      count: String(limit),
    });
    if (typeof args.deputy_slug === 'string' && args.deputy_slug) params.set('parlementaire', args.deputy_slug);
    if (typeof args.date_from === 'string' && args.date_from) params.set('date_min', args.date_from);
    if (typeof args.date_to === 'string' && args.date_to) params.set('date_max', args.date_to);
    return this.ndRequest(`${base}/interventions/json?${params}`);
  }

  private async searchQuestions(args: Record<string, unknown>): Promise<ToolResult> {
    const base = this.legBase(args.legislature);
    const limit = typeof args.limit === 'number'
      ? Math.min(100, Math.max(1, args.limit))
      : 25;
    const params = new URLSearchParams({
      format: 'json',
      count: String(limit),
    });
    if (typeof args.query === 'string' && args.query) params.set('recherche', args.query);
    if (typeof args.deputy_slug === 'string' && args.deputy_slug) params.set('parlementaire', args.deputy_slug);
    if (typeof args.type === 'string' && args.type) params.set('type', args.type);
    return this.ndRequest(`${base}/questions/json?${params}`);
  }

  private async listVotes(args: Record<string, unknown>): Promise<ToolResult> {
    const base = this.legBase(args.legislature);
    const limit = typeof args.limit === 'number'
      ? Math.min(100, Math.max(1, args.limit))
      : 25;
    const params = new URLSearchParams({ count: String(limit) });
    if (typeof args.deputy_slug === 'string' && args.deputy_slug) params.set('parlementaire', args.deputy_slug);
    return this.ndRequest(`${base}/votes/json?${params}`);
  }

  private async listGroups(args: Record<string, unknown>): Promise<ToolResult> {
    const base = this.legBase(args.legislature);
    return this.ndRequest(`${base}/organismes/groupe/json`);
  }
}
