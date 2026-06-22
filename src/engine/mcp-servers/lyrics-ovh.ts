/**
 * Lyrics OVH MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.lyrics.ovh
// Auth: none (public, keyless)
// Docs: https://lyricsovh.docs.apiary.io/
// Category: entertainment
// Rate limits: not publicly documented; no API key required

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

export class LyricsOvhMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('LyricsOvhMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? 'https://api.lyrics.ovh';
  }

  static catalog() {
    return {
      name: 'lyrics-ovh',
      displayName: 'Lyrics OVH',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'lyrics', 'song lyrics', 'music', 'artist', 'songs', 'track',
        'search', 'suggest', 'ovh', 'free lyrics', 'lyrics lookup',
      ],
      toolNames: ['lyrics', 'suggest'],
      description: 'Lyrics OVH: look up song lyrics by artist and title, or get title/artist suggestions for a free-form query — keyless and public.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'none' as const,
        probeState: 'no-auth-verified' as const,
      },
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'lyrics',
        description: 'Exact-name lookup. Returns the lyrics text for an (artist, title) pair.',
        inputSchema: {
          type: 'object',
          properties: {
            artist: { type: 'string', description: 'Artist name, e.g. "Coldplay"' },
            title:  { type: 'string', description: 'Song title, e.g. "Yellow"' },
          },
          required: ['artist', 'title'],
        },
      },
      {
        name: 'suggest',
        description: 'Title/artist suggestions for a free-form query (results have track + artist info).',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Free-form search query, e.g. "yellow coldplay"' },
            limit: { type: 'number',  description: '1–50 results to return (default 10)' },
          },
          required: ['query'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'lyrics':  return this.getLyrics(args);
        case 'suggest': return this.getSuggestions(args);
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

  private reqStr(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing. Pass a string like ${example}.`);
    }
    return v;
  }

  private async getLyrics(args: Record<string, unknown>): Promise<ToolResult> {
    const artist = this.reqStr(args, 'artist', '"Coldplay"');
    const title  = this.reqStr(args, 'title',  '"Yellow"');
    const url = `${this.baseUrl}/v1/${encodeURIComponent(artist)}/${encodeURIComponent(title)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: `Lyrics not found for "${artist} — ${title}". Try the suggest tool first.` }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async getSuggestions(args: Record<string, unknown>): Promise<ToolResult> {
    const query = this.reqStr(args, 'query', '"yellow coldplay"');
    const limit = Math.min(50, Math.max(1, typeof args.limit === 'number' ? args.limit : 10));
    const url = `${this.baseUrl}/suggest/${encodeURIComponent(query)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const json = await response.json() as { data?: unknown[]; total?: number };
    const result = { total: json.total ?? 0, data: (json.data ?? []).slice(0, limit) };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
