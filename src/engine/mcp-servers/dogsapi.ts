/**
 * Dog API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://dogapi.dog (free, no auth required)
// Base URL: https://dogapi.dog/api/v2
// Docs: https://dogapi.dog/docs/api-v2
// Category: animals
// Rate limits: None documented (public free API)

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://dogapi.dog/api/v2';

export class DogsAPIMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'dogsapi',
      displayName: 'Dog API',
      version: '1.0.0',
      category: 'animals',
      keywords: [
        'dogs', 'dog', 'breeds', 'dog breeds', 'canine', 'facts', 'dog facts',
        'animals', 'pets', 'groups', 'breed groups', 'hypoallergenic',
        'life span', 'weight',
      ],
      toolNames: ['list_breeds', 'get_breed', 'list_facts', 'get_groups'],
      description: 'Dog API: browse dog breeds with weight and life-span details, retrieve a specific breed by ID, fetch random dog facts, and list breed groups.',
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
        name: 'list_breeds',
        description: 'Get a paginated list of dog breeds with details including weight, life span, and hypoallergenic status.',
        inputSchema: {
          type: 'object',
          properties: {
            page: {
              type: 'number',
              description: 'Page number for pagination (default: 1)',
            },
          },
        },
      },
      {
        name: 'get_breed',
        description: 'Get detailed information about a specific dog breed by its ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'The breed ID (obtained from list_breeds)',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'list_facts',
        description: 'Get a list of random dog facts.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Number of facts to return (default: 10, max: 100)',
            },
          },
        },
      },
      {
        name: 'get_groups',
        description: 'Get all dog breed groups (e.g., Sporting, Herding, Terrier).',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_breeds':  return this.listBreeds((args.page as number | undefined) ?? 1);
        case 'get_breed':    return this.getBreed(args.id as string);
        case 'list_facts':   return this.listFacts((args.limit as number | undefined) ?? 10);
        case 'get_groups':   return this.getGroups();
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

  private async listBreeds(page: number): Promise<ToolResult> {
    const response = await this.fetchWithRetry(
      `${BASE_URL}/breeds?page[number]=${encodeURIComponent(String(page))}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = await response.json() as {
      data: Array<{ id: string; type: string; attributes: { name: string; description: string; life: { min: number; max: number }; male_weight: { min: number; max: number }; female_weight: { min: number; max: number }; hypoallergenic: boolean } }>;
      links?: { self: string; next?: string; last?: string };
      meta?: { count: number };
    };
    const result = {
      page,
      total: data.meta?.count ?? null,
      breeds: data.data.map((b) => ({
        id: b.id,
        name: b.attributes.name,
        description: b.attributes.description,
        life_span_years: b.attributes.life,
        male_weight_kg: b.attributes.male_weight,
        female_weight_kg: b.attributes.female_weight,
        hypoallergenic: b.attributes.hypoallergenic,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getBreed(id: string): Promise<ToolResult> {
    const response = await this.fetchWithRetry(
      `${BASE_URL}/breeds/${encodeURIComponent(id)}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = await response.json() as {
      data: { id: string; type: string; attributes: { name: string; description: string; life: { min: number; max: number }; male_weight: { min: number; max: number }; female_weight: { min: number; max: number }; hypoallergenic: boolean } };
    };
    const b = data.data;
    const result = {
      id: b.id,
      name: b.attributes.name,
      description: b.attributes.description,
      life_span_years: b.attributes.life,
      male_weight_kg: b.attributes.male_weight,
      female_weight_kg: b.attributes.female_weight,
      hypoallergenic: b.attributes.hypoallergenic,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async listFacts(limit: number): Promise<ToolResult> {
    const response = await this.fetchWithRetry(
      `${BASE_URL}/facts?limit=${encodeURIComponent(String(limit))}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = await response.json() as {
      data: Array<{ id: string; type: string; attributes: { body: string } }>;
    };
    const result = {
      count: data.data.length,
      facts: data.data.map((f) => ({ id: f.id, fact: f.attributes.body })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getGroups(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(
      `${BASE_URL}/groups`,
      { method: 'GET', headers: { Accept: 'application/json' } },
    );
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return { content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }], isError: true };
    }
    const data = await response.json() as {
      data: Array<{ id: string; type: string; attributes: { name: string } }>;
    };
    const result = {
      count: data.data.length,
      groups: data.data.map((g) => ({ id: g.id, name: g.attributes.name })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}
