/**
 * Cleveland Museum of Art Open Access API — MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Base URL: https://openaccess-api.clevelandart.org/api
 * Auth: none (public Open Access API)
 * Docs: https://openaccess-api.clevelandart.org/
 * Category: arts
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://openaccess-api.clevelandart.org/api';

export class ClevelandArtMCPServer extends MCPAdapterBase {
  static catalog() {
    return {
      name: 'clevelandart',
      displayName: 'Cleveland Museum of Art Open Access',
      version: '1.0.0',
      category: 'arts',
      keywords: [
        'cleveland', 'museum', 'art', 'open access', 'artworks', 'paintings',
        'sculpture', 'drawings', 'collections', 'exhibitions', 'artists',
        'creators', 'cc0', 'public domain', 'fine art', 'cultural heritage',
      ],
      toolNames: ['search', 'get_artwork', 'creators', 'exhibitions'],
      description: 'Cleveland Museum of Art Open Access API: search artworks, retrieve artwork details, browse creators, and explore exhibitions from the museum\'s open-access collection.',
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
        description: 'Search artworks in the Cleveland Museum of Art collection. Optional filters: type, artist, has_image, cc0.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Free-text search across title, description, and artist.',
            },
            type: {
              type: 'string',
              description: 'Artwork type filter, e.g. "Painting", "Sculpture", "Drawing".',
            },
            artist: {
              type: 'string',
              description: 'Filter by artist name.',
            },
            has_image: {
              type: 'boolean',
              description: 'Restrict results to artworks that have a web image.',
            },
            cc0: {
              type: 'boolean',
              description: 'Restrict results to CC0-licensed images.',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (1–1000, default 25).',
            },
            skip: {
              type: 'number',
              description: 'Number of results to skip for pagination (default 0).',
            },
          },
        },
      },
      {
        name: 'get_artwork',
        description: 'Retrieve a single artwork by accession number (e.g. "1962.158") or numeric ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Accession number (e.g. "1962.158") or numeric artwork ID (e.g. "94979").',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'creators',
        description: 'Search creators (artists) in the Cleveland Museum of Art collection by name.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Name or partial name of the creator to search for.',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (1–1000, default 25).',
            },
          },
        },
      },
      {
        name: 'exhibitions',
        description: 'Search exhibitions at the Cleveland Museum of Art by title or keyword.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Exhibition title or keyword to search for.',
            },
            limit: {
              type: 'number',
              description: 'Number of results to return (1–1000, default 25).',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search':      return this.search(args);
        case 'get_artwork': return this.getArtwork(args);
        case 'creators':    return this.creators(args);
        case 'exhibitions': return this.exhibitions(args);
        default:
          return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
      }
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
        }],
        isError: true,
      };
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

  private async get(path: string): Promise<ToolResult> {
    const url = `${BASE_URL}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'Cleveland Art: not found' }], isError: true };
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

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    if (args.query)     params.set('q',       String(args.query));
    if (args.type)      params.set('type',    String(args.type));
    if (args.artist)    params.set('artists', String(args.artist));
    if (args.has_image) params.set('has_image', '1');
    if (args.cc0)       params.set('cc0',     '1');
    params.set('limit', String(Math.min(1000, Math.max(1, (args.limit as number) ?? 25))));
    params.set('skip',  String(Math.max(0, (args.skip as number) ?? 0)));
    return this.get(`/artworks?${params.toString()}`);
  }

  private async getArtwork(args: Record<string, unknown>): Promise<ToolResult> {
    const id = args.id;
    if (typeof id !== 'string' || !id.trim()) {
      return {
        content: [{ type: 'text', text: 'Required argument "id" is missing. Pass an accession number like "1962.158" or a numeric ID like "94979".' }],
        isError: true,
      };
    }
    return this.get(`/artworks/${encodeURIComponent(id.trim())}`);
  }

  private async creators(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    if (args.query) params.set('name', String(args.query));
    params.set('limit', String(Math.min(1000, Math.max(1, (args.limit as number) ?? 25))));
    return this.get(`/creators?${params.toString()}`);
  }

  private async exhibitions(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams();
    if (args.query) params.set('title', String(args.query));
    params.set('limit', String(Math.min(1000, Math.max(1, (args.limit as number) ?? 25))));
    return this.get(`/exhibitions?${params.toString()}`);
  }
}
