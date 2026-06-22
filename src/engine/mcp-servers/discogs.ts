/**
 * Discogs MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.discogs.com
// Auth: Authorization header — Discogs token=<personal_access_token>
//       Token generated at https://www.discogs.com/settings/developers
// Docs: https://www.discogs.com/developers
// Category: entertainment
// Rate limits: 60 req/min (authenticated)

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface DiscogsConfig {
  apiKey: string;
  baseUrl?: string;
}

const DISCOGS_USER_AGENT = 'EpicAI-Discogs-Adapter/1.0 (contact@protectnil.com)';

export class DiscogsMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: DiscogsConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Discogs: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('Discogs: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api.discogs.com';
  }

  static catalog() {
    return {
      name: 'discogs',
      displayName: 'Discogs',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'discogs', 'music', 'vinyl', 'records', 'album', 'release', 'pressing',
        'tracklist', 'artist', 'label', 'genre', 'format', 'catalog', 'discography',
        'marketplace', 'collector', 'master release', 'barcode', 'country',
      ],
      toolNames: ['search', 'get_release', 'get_master', 'get_artist', 'get_label'],
      description:
        'Discogs: the most complete release-level music catalog — search across releases, masters, artists, and labels; retrieve full detail on vinyl pressings, tracklists, credits, formats, identifiers, and label discographies.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'api-key' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'search',
        description:
          'Full-text search across Discogs (releases, masters, artists, labels). Filter by type, title, artist, format (e.g., "Vinyl", "CD"), country, year, genre, style, label.',
        inputSchema: {
          type: 'object',
          properties: {
            query:    { type: 'string',  description: 'Free-text query' },
            type:     { type: 'string',  description: 'release | master | artist | label' },
            title:    { type: 'string',  description: 'Title filter' },
            artist:   { type: 'string',  description: 'Artist filter' },
            label:    { type: 'string',  description: 'Label filter' },
            format:   { type: 'string',  description: 'e.g., "Vinyl", "CD", "Album"' },
            country:  { type: 'string',  description: 'Country of release' },
            year:     { type: 'string',  description: 'Release year or year-range' },
            genre:    { type: 'string',  description: 'Genre filter' },
            style:    { type: 'string',  description: 'Style filter' },
            page:     { type: 'number',  description: '1-based page number' },
            per_page: { type: 'number',  description: 'Results per page: 1–100 (default 25)' },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_release',
        description:
          'Full release detail: title, artists, labels, formats, tracklist, credits, year, country, notes, identifiers (barcode, matrix), data quality.',
        inputSchema: {
          type: 'object',
          properties: {
            release_id: { type: 'number', description: 'Discogs release ID' },
          },
          required: ['release_id'],
        },
      },
      {
        name: 'get_master',
        description: 'Master release detail — the canonical work across all editions and pressings.',
        inputSchema: {
          type: 'object',
          properties: {
            master_id: { type: 'number', description: 'Discogs master ID' },
          },
          required: ['master_id'],
        },
      },
      {
        name: 'get_artist',
        description: 'Artist profile and identifiers.',
        inputSchema: {
          type: 'object',
          properties: {
            artist_id: { type: 'number', description: 'Discogs artist ID' },
          },
          required: ['artist_id'],
        },
      },
      {
        name: 'get_label',
        description: 'Label profile, parent label, and sublabels.',
        inputSchema: {
          type: 'object',
          properties: {
            label_id: { type: 'number', description: 'Discogs label ID' },
          },
          required: ['label_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search':      return this.search(args);
        case 'get_release': return this.getRelease(args);
        case 'get_master':  return this.getMaster(args);
        case 'get_artist':  return this.getArtist(args);
        case 'get_label':   return this.getLabel(args);
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

  // ── Private helpers ─────────────────────────────────────────────────────────

  private authHeaders(): Record<string, string> {
    return {
      Authorization: `Discogs token=${this.apiKey}`,
      'User-Agent': DISCOGS_USER_AGENT,
      Accept: 'application/vnd.discogs.v2.discogs+json',
    };
  }

  private async discogsGet(path: string, params?: URLSearchParams): Promise<ToolResult> {
    const qs = params?.toString() ? `?${params.toString()}` : '';
    const url = `${this.baseUrl}${path}${qs}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: this.authHeaders(),
    });
    if (response.status === 401 || response.status === 403) {
      return {
        content: [{ type: 'text', text: 'Discogs: unauthorized — check the personal access token' }],
        isError: true,
      };
    }
    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: 'Discogs: resource not found (HTTP 404)' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Discogs API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private requireNumber(args: Record<string, unknown>, key: string, example: string): number {
    const v = args[key];
    if (typeof v !== 'number' || !Number.isFinite(v)) {
      throw new Error(`Required argument "${key}" must be a finite number. Example: ${example}.`);
    }
    return v;
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ q: String(args.query) });
    for (const k of ['type', 'title', 'artist', 'label', 'format', 'country', 'year', 'genre', 'style']) {
      if (args[k] !== undefined && args[k] !== null && args[k] !== '') {
        params.set(k, String(args[k]));
      }
    }
    const page = typeof args.page === 'number' ? Math.max(1, args.page) : 1;
    const perPage = typeof args.per_page === 'number' ? Math.min(100, Math.max(1, args.per_page)) : 25;
    params.set('page', String(page));
    params.set('per_page', String(perPage));
    return this.discogsGet('/database/search', params);
  }

  private async getRelease(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireNumber(args, 'release_id', '249504');
    return this.discogsGet(`/releases/${id}`);
  }

  private async getMaster(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireNumber(args, 'master_id', '15');
    return this.discogsGet(`/masters/${id}`);
  }

  private async getArtist(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireNumber(args, 'artist_id', '108713');
    return this.discogsGet(`/artists/${id}`);
  }

  private async getLabel(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireNumber(args, 'label_id', '1');
    return this.discogsGet(`/labels/${id}`);
  }
}
