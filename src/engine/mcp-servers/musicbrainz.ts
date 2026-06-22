/**
 * MusicBrainz MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: MusicBrainz Web Service v2 (free, no auth required)
// Base URL: https://musicbrainz.org/ws/2
// Docs: https://musicbrainz.org/doc/MusicBrainz_API
// Category: music
// Rate limits: 1 request/second per IP (no API key required)

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://musicbrainz.org/ws/2';

export class MusicBrainzMCPServer extends MCPAdapterBase {
  private readonly userAgent: string;

  constructor() {
    super();
    this.userAgent = 'epic-ai-chariot/1.0.0 (https://epic-ai.com)';
  }

  static catalog() {
    return {
      name: 'musicbrainz',
      displayName: 'MusicBrainz',
      version: '1.0.0',
      category: 'music',
      keywords: [
        'musicbrainz', 'music', 'artist', 'album', 'release', 'track',
        'discography', 'band', 'song', 'recording', 'mbid', 'metadata',
        'music database', 'open music encyclopedia',
      ],
      toolNames: ['search_artists', 'get_artist', 'search_releases', 'get_release'],
      description: 'MusicBrainz Web Service v2: search and retrieve detailed music metadata including artists, albums, and track listings from the open music encyclopedia.',
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
        name: 'search_artists',
        description: 'Search for music artists by name using the MusicBrainz database.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Artist name or search query.',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of results to return. Defaults to 10.',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_artist',
        description: 'Get detailed information about an artist including their release list. Use the MusicBrainz ID from search_artists.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'MusicBrainz artist ID (UUID).',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'search_releases',
        description: 'Search for albums and releases by title or query.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Release title or search query.',
            },
            limit: {
              type: 'number',
              description: 'Maximum number of results to return. Defaults to 10.',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_release',
        description: 'Get detailed information about a release including its full track listing. Use the MusicBrainz ID from search_releases.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'MusicBrainz release ID (UUID).',
            },
          },
          required: ['id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_artists':  return this.searchArtists(args);
        case 'get_artist':      return this.getArtist(args);
        case 'search_releases': return this.searchReleases(args);
        case 'get_release':     return this.getRelease(args);
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

  private async request(path: string): Promise<ToolResult> {
    const separator = path.includes('?') ? '&' : '?';
    const url = `${BASE_URL}${path}${separator}fmt=json`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'User-Agent': this.userAgent,
      },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchArtists(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const limit = (args.limit as number | undefined) ?? 10;
    const params = new URLSearchParams({
      query,
      limit: String(limit),
    });
    return this.request(`/artist?${params.toString()}`);
  }

  private async getArtist(args: Record<string, unknown>): Promise<ToolResult> {
    const id = encodeURIComponent(args.id as string);
    return this.request(`/artist/${id}?inc=releases`);
  }

  private async searchReleases(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const limit = (args.limit as number | undefined) ?? 10;
    const params = new URLSearchParams({
      query,
      limit: String(limit),
    });
    return this.request(`/release?${params.toString()}`);
  }

  private async getRelease(args: Record<string, unknown>): Promise<ToolResult> {
    const id = encodeURIComponent(args.id as string);
    return this.request(`/release/${id}?inc=recordings`);
  }
}
