/**
 * Fruityvice MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://www.fruityvice.com/api/fruit
// Auth: none (public, unauthenticated)
// Docs: https://www.fruityvice.com/#documentation
// Category: food
// Tools: get_fruit, list_fruits, get_by_nutrition

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

export class FruityviceMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('FruityviceMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl || 'https://www.fruityvice.com/api/fruit';
  }

  static catalog() {
    return {
      name: 'fruityvice',
      displayName: 'Fruityvice',
      version: '1.0.0',
      category: 'food',
      keywords: [
        'fruit', 'nutrition', 'food', 'calories', 'sugar', 'fat',
        'carbohydrates', 'protein', 'diet', 'health', 'fruityvice',
        'botanical', 'family', 'genus',
      ],
      toolNames: ['get_fruit', 'list_fruits', 'get_by_nutrition'],
      description: 'Fruityvice: retrieve nutritional data for fruits by name, list all available fruits, or filter fruits by a nutritional range.',
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
        name: 'get_fruit',
        description: 'Get detailed nutritional information for a specific fruit by name.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'The name of the fruit (e.g., "banana", "apple", "mango").',
            },
          },
          required: ['name'],
        },
      },
      {
        name: 'list_fruits',
        description: 'List all available fruits with their complete nutritional data.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_by_nutrition',
        description:
          'Find fruits within a nutritional range for a specific nutrient. Useful for filtering fruits by calories, sugar, fat, carbohydrates, or protein.',
        inputSchema: {
          type: 'object',
          properties: {
            nutrient: {
              type: 'string',
              description:
                'The nutrient to filter by. One of: calories, sugar, fat, carbohydrates, protein.',
            },
            min: {
              type: 'number',
              description: 'Minimum value for the nutrient (inclusive).',
            },
            max: {
              type: 'number',
              description: 'Maximum value for the nutrient (inclusive).',
            },
          },
          required: ['nutrient', 'min', 'max'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_fruit':       return this.getFruit(args.name as string);
        case 'list_fruits':     return this.listFruits();
        case 'get_by_nutrition': return this.getByNutrition(
          args.nutrient as string,
          args.min as number,
          args.max as number,
        );
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

  private async getFruit(name: string): Promise<ToolResult> {
    const url = `${this.baseUrl}/${encodeURIComponent(name.toLowerCase())}`;
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

  private async listFruits(): Promise<ToolResult> {
    const url = `${this.baseUrl}/all`;
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
    const data = await response.json() as unknown[];
    return {
      content: [{ type: 'text', text: this.truncate({ count: data.length, fruits: data }) }],
      isError: false,
    };
  }

  private async getByNutrition(nutrient: string, min: number, max: number): Promise<ToolResult> {
    const params = new URLSearchParams({ min: String(min), max: String(max) });
    const url = `${this.baseUrl}/${encodeURIComponent(nutrient.toLowerCase())}?${params.toString()}`;
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
    const data = await response.json() as unknown[];
    return {
      content: [{ type: 'text', text: this.truncate({ nutrient, min, max, count: data.length, fruits: data }) }],
      isError: false,
    };
  }
}
