/**
 * Cat Facts API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: https://catfact.ninja
// Auth: none (public, no key required)
// Docs: https://catfact.ninja
// Category: entertainment
// Rate limits: none documented

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://catfact.ninja';

interface RawFact {
  fact: string;
  length: number;
}

interface RawFactsResponse {
  current_page: number;
  data: RawFact[];
  total: number;
  per_page: number;
}

interface RawBreed {
  breed: string;
  country: string;
  origin: string;
  coat: string;
  pattern: string;
}

interface RawBreedsResponse {
  current_page: number;
  data: RawBreed[];
  total: number;
  per_page: number;
}

export class CatFactsMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('CatFactsMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'catfacts',
      displayName: 'Cat Facts',
      version: '1.0.0',
      category: 'entertainment',
      keywords: [
        'cat', 'cats', 'facts', 'cat facts', 'animals', 'trivia',
        'breeds', 'feline', 'random fact', 'fun facts',
      ],
      toolNames: ['get_fact', 'get_facts', 'list_breeds'],
      description: 'Cat Facts API: retrieve random cat facts and browse cat breed details — free and unauthenticated.',
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
        name: 'get_fact',
        description: 'Get a single random cat fact.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_facts',
        description: 'Get multiple random cat facts.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of facts to return. Defaults to 5.',
            },
          },
        },
      },
      {
        name: 'list_breeds',
        description: 'List cat breeds with details such as country, origin, coat, and pattern.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of breeds to return. Defaults to 10.',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_fact':   return this.getFact();
        case 'get_facts':  return this.getFacts((args.limit as number | undefined) ?? 5);
        case 'list_breeds': return this.listBreeds((args.limit as number | undefined) ?? 10);
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

  private async getFact(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${this.baseUrl}/fact`, {
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
    const data = (await response.json()) as RawFact;
    return {
      content: [{ type: 'text', text: this.truncate({ fact: data.fact, length: data.length }) }],
      isError: false,
    };
  }

  private async getFacts(limit: number): Promise<ToolResult> {
    const url = `${this.baseUrl}/facts?limit=${encodeURIComponent(String(limit))}`;
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
    const data = (await response.json()) as RawFactsResponse;
    const result = {
      total: data.total,
      facts: data.data.map((f) => ({ fact: f.fact, length: f.length })),
    };
    return {
      content: [{ type: 'text', text: this.truncate(result) }],
      isError: false,
    };
  }

  private async listBreeds(limit: number): Promise<ToolResult> {
    const url = `${this.baseUrl}/breeds?limit=${encodeURIComponent(String(limit))}`;
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
    const data = (await response.json()) as RawBreedsResponse;
    const result = {
      total: data.total,
      breeds: data.data.map((b) => ({
        breed: b.breed,
        country: b.country,
        origin: b.origin,
        coat: b.coat,
        pattern: b.pattern,
      })),
    };
    return {
      content: [{ type: 'text', text: this.truncate(result) }],
      isError: false,
    };
  }
}
