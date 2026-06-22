/**
 * Superhero API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://akabab.github.io/superhero-api (free, no auth, static JSON)
// Base URL: https://akabab.github.io/superhero-api/api
// Auth: none
// Docs: https://akabab.github.io/superhero-api/
// Category: entertainment
// Rate limits: none (static GitHub Pages hosting)

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

export class SuperheroMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('SuperheroMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? 'https://akabab.github.io/superhero-api/api';
  }

  static catalog() {
    return {
      name: 'superhero',
      displayName: 'Superhero API',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'superhero', 'superheroes', 'comics', 'marvel', 'dc',
        'powerstats', 'biography', 'heroes', 'villains',
        'intelligence', 'strength', 'speed', 'combat',
      ],
      toolNames: ['list_all', 'get_hero', 'get_powerstats', 'get_biography'],
      description: 'Superhero API: browse all superheroes and retrieve full profiles, power statistics, and biography details — free and unauthenticated.',
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
        name: 'list_all',
        description: 'List all superheroes in the database with their IDs, names, and slugs.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_hero',
        description: 'Get full data for a superhero by their numeric ID, including powerstats, biography, appearance, work, connections, and images.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Numeric superhero ID (1-731)',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'get_powerstats',
        description: 'Get power statistics (intelligence, strength, speed, durability, power, combat) for a superhero by ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Numeric superhero ID (1-731)',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'get_biography',
        description: 'Get biography details (full name, aliases, publisher, first appearance, alignment) for a superhero by ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'number',
              description: 'Numeric superhero ID (1-731)',
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
        case 'list_all':      return this.listAll();
        case 'get_hero':      return this.getHero(args.id as number);
        case 'get_powerstats': return this.getPowerstats(args.id as number);
        case 'get_biography': return this.getBiography(args.id as number);
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

  private async listAll(): Promise<ToolResult> {
    const url = `${this.baseUrl}/all.json`;
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
    const data = (await response.json()) as Array<{ id: number; name: string; slug: string }>;
    const summary = {
      count: data.length,
      heroes: data.map((h) => ({ id: h.id, name: h.name, slug: h.slug })),
    };
    return { content: [{ type: 'text', text: this.truncate(summary) }], isError: false };
  }

  private async getHero(id: number): Promise<ToolResult> {
    return this.request(`/id/${id}.json`);
  }

  private async getPowerstats(id: number): Promise<ToolResult> {
    return this.request(`/powerstats/${id}.json`);
  }

  private async getBiography(id: number): Promise<ToolResult> {
    return this.request(`/biography/${id}.json`);
  }
}
