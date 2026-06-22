/**
 * Rick and Morty API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream confirmed from open-source MCP wrapper (MIT) for The Rick and Morty API.
// This file calls the real upstream directly. No proxy or gateway is involved.
//
// Base URL: https://rickandmortyapi.com/api
// Auth: None required — The Rick and Morty API is public and free with no auth.
// Docs: https://rickandmortyapi.com/documentation
// Rate limits: None documented; reasonable use expected.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface RickMortyConfig {
  /** Optional base URL override (default: https://rickandmortyapi.com/api) */
  baseUrl?: string;
}

export class RickMortyMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config: RickMortyConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Rick and Morty API: configuration object is required');
    }
    this.baseUrl = config.baseUrl ?? 'https://rickandmortyapi.com/api';
  }

  static catalog() {
    return {
      name: 'rickmorty',
      displayName: 'Rick and Morty API',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'rick and morty', 'rick', 'morty', 'characters', 'episodes',
        'locations', 'tv show', 'animation', 'adult swim', 'sci-fi',
        'free', 'public api', 'open data',
      ],
      toolNames: ['search_characters', 'get_character', 'get_location', 'get_episode'],
      description: 'Rick and Morty API: search characters by name, retrieve character/location/episode details by ID — all free and unauthenticated.',
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
        name: 'search_characters',
        description: 'Search for Rick and Morty characters by name. Returns a list of matching characters.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Character name to search for (e.g. "Rick", "Morty", "Beth").',
            },
          },
          required: ['name'],
        },
      },
      {
        name: 'get_character',
        description: 'Get detailed information about a specific Rick and Morty character by their ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Character ID (e.g. 1 for Rick Sanchez).',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'get_location',
        description: 'Get details about a specific Rick and Morty location by its ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Location ID (e.g. 1 for Earth (C-137)).',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'get_episode',
        description: 'Get details about a specific Rick and Morty episode by its ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Episode ID (e.g. 1 for "Pilot").',
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
        case 'search_characters': return this.searchCharacters(args);
        case 'get_character':     return this.getCharacter(args);
        case 'get_location':      return this.getLocation(args);
        case 'get_episode':       return this.getEpisode(args);
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
    const url = `${this.baseUrl}${path}`;
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
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchCharacters(args: Record<string, unknown>): Promise<ToolResult> {
    const name = encodeURIComponent(args.name as string);
    return this.request(`/character/?name=${name}`);
  }

  private async getCharacter(args: Record<string, unknown>): Promise<ToolResult> {
    const id = Number(args.id);
    return this.request(`/character/${id}`);
  }

  private async getLocation(args: Record<string, unknown>): Promise<ToolResult> {
    const id = Number(args.id);
    return this.request(`/location/${id}`);
  }

  private async getEpisode(args: Record<string, unknown>): Promise<ToolResult> {
    const id = Number(args.id);
    return this.request(`/episode/${id}`);
  }
}
